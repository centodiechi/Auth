package authservice

import (
	apex "auth/protos/v1"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"golang.org/x/net/context"
)

type HTTPServer struct {
	AuthService *AuthSvc
}

func NewHTTPServer(authService *AuthSvc) *HTTPServer {
	return &HTTPServer{AuthService: authService}
}

func (s *HTTPServer) Routes() http.Handler {
	r := chi.NewRouter()

	r.Post("/signup", s.SignupHandler)
	r.Post("/login", s.LoginHandler)
	r.Post("/refresh", s.RefreshTokenHandler)

	r.With(JWTMiddleware).Get("/verify", s.VerifyTokenHandler)

	return r
}

func (s *HTTPServer) SignupHandler(w http.ResponseWriter, r *http.Request) {
	var req apex.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	resp, err := s.AuthService.Signup(context.Background(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *HTTPServer) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req apex.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	resp, err := s.AuthService.Login(context.Background(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *HTTPServer) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req apex.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	resp, err := s.AuthService.RefreshToken(context.Background(), &req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *HTTPServer) VerifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	if token == "" {
		http.Error(w, "missing token", http.StatusUnauthorized)
		return
	}

	token = strings.TrimPrefix(token, "Bearer ")
	req := &apex.VerifyTokenRequest{Token: token}

	resp, err := s.AuthService.VerifyToken(context.Background(), req)
	if err != nil || !resp.Valid {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
		claims, err := Verify_(tokenStr)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "user_id", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
