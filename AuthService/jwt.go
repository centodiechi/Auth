package authservice

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("@A838-k#$e&y%*|")

func GenerateToken(userID, tokenType string, expiryMinutes int) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"type":    tokenType,
		"ttl":     time.Now().Add(time.Minute * time.Duration(expiryMinutes)).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func Verify_(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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
