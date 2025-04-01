package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("@A838-k#$e&y%*|")

type userID string

const UserIDKey userID = "user_id"

func GenerateRefreshToken(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    "refresh",
		"ttl":     time.Now().Add(24 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func GenerateAccessToken(userID, refreshToken string) (string, error) {
	encodedRefresh := base64.StdEncoding.EncodeToString([]byte(refreshToken))
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    "access",
		"ttl":     time.Now().Add(15 * time.Minute).Unix(),
		"refresh": encodedRefresh,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func verify_(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	exp, ok := claims["ttl"].(float64)
	if !ok || time.Now().Unix() > int64(exp) {
		return "", errors.New("token expired")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", errors.New("invalid token payload")
	}

	return userID, nil
}

func JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "missing token", http.StatusUnauthorized)
			return
		}

		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
		claims, err := verify_(tokenStr)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserIDKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
