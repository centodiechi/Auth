package authservice

import (
	"encoding/json"
	"net/http"

	middleware "github.com/centodiechi/Auth/jwtmiddleware"
	apex "github.com/centodiechi/Auth/protos/v1"

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
	r.Post("/refresh-token", s.RefreshTokenHandler)

	r.With(middleware.JWTMiddleware).Post("/logout", s.LogoutHandler)
	r.With(middleware.JWTMiddleware).Get("/verify", s.VerifyHandler)

	r.Route("/admin", func(r chi.Router) {
		r.Use(middleware.JWTMiddleware)
		r.Use(middleware.RoleMiddleware("ADMIN"))
	})

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

	w.WriteHeader(http.StatusCreated)
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

func (s *HTTPServer) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(middleware.UserIDKey).(string)
	if userID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if _, err := s.AuthService.Logout(context.Background(), &apex.LogoutRequest{UserId: userID}); err != nil {
		http.Error(w, "failed to logout", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Successfully logged out"})
}

func (s *HTTPServer) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	var refreshToken string

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	refreshToken = req.RefreshToken

	if refreshToken == "" {
		http.Error(w, "refresh token is required", http.StatusBadRequest)
		return
	}

	resp, err := s.AuthService.RefreshToken(context.Background(), &apex.RefreshTokenRequest{
		RefreshToken: refreshToken,
	})

	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token": resp.AccessToken,
	})
}

func (s *HTTPServer) VerifyHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value(middleware.UserIDKey).(string)
	role := r.Context().Value(middleware.UserRoleKey).(string)

	if userID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"valid":   "true",
		"user_id": userID,
		"role":    role,
	})
}
