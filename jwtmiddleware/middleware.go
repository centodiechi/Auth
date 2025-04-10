package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"encoding/base64"

	"slices"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("@A838-k#$e&y%*|")
var refreshSecretKey = []byte("R$3fr3sh-S3cr3t-K3y!")

type userID string
type userRole string

const UserIDKey userID = "user_id"
const UserRoleKey userRole = "user_role"

type AccessTokenClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	UserID string `json:"user_id"`
	jwt.RegisteredClaims
}

func GenerateAccessToken(userID string, role string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"role":    role,
		"exp":     time.Now().Add(30 * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	encodedToken := base64.StdEncoding.EncodeToString([]byte(tokenString))
	return encodedToken, nil
}

func GenerateRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(7 * 24 * time.Hour).Unix(), // 7 days
		"iat":     time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(refreshSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func ExtractTokenFromHeader(r *http.Request) string {
	tokenStr := r.Header.Get("Authorization")
	encodedToken := strings.TrimPrefix(tokenStr, "Bearer ")
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedToken)
	if err != nil {
		return encodedToken
	}
	return string(decodedBytes)
}

func VerifyToken(tokenString string) (string, string, error) {
	claims := &AccessTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		return "", "", errors.New("invalid token")
	}

	if claims.UserID == "" {
		return "", "", errors.New("invalid user_id in token")
	}

	role := claims.Role
	if role == "" {
		role = "USER"
	}

	return claims.UserID, role, nil
}

func VerifyRefreshToken(tokenString string) (string, error) {
	claims := &RefreshTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return refreshSecretKey, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid refresh token")
	}

	if claims.UserID == "" {
		return "", errors.New("invalid user_id in token")
	}

	return claims.UserID, nil
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := ExtractTokenFromHeader(r)
		if tokenStr == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		userID, role, err := VerifyToken(tokenStr)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, userID)
		ctx = context.WithValue(ctx, UserRoleKey, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RoleMiddleware(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, ok := r.Context().Value(UserRoleKey).(string)
			if !ok {
				http.Error(w, "unauthorized: missing role", http.StatusUnauthorized)
				return
			}

			hasRole := slices.Contains(roles, role)

			if !hasRole {
				http.Error(w, "forbidden: insufficient privileges", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
