package authservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	middleware "github.com/centodiechi/Auth/jwtmiddleware"
	apex "github.com/centodiechi/Auth/protos/v1"

	redis "github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

type User struct {
	UserID    string `gorm:"primaryKey"`
	Name      string
	Email     string `gorm:"unique"`
	Password  string
	CreatedAt time.Time
}

type Token struct {
	ID        uint   `gorm:"primaryKey"`
	UserID    string `gorm:"index"`
	TokenType string `gorm:"index"`
	Token     string `gorm:"unique"`
	CreatedAt time.Time
	TTL       time.Time
}

type AuthSvc struct {
	apex.UnimplementedAuthServiceServer
	RedisClient *redis.Client
	DB          *gorm.DB
}

func (auth *AuthSvc) Signup(ctx context.Context, req *apex.SignupRequest) (*apex.SignupResponse, error) {
	var existingUser User
	result := auth.DB.Where("email = ?", req.Email).First(&existingUser)
	if result.Error == nil {
		return nil, errors.New("user already exists")
	} else if result.Error != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("error checking existing user: %w", result.Error)
	}

	userID, err := auth.getNextHexID(ctx, "user_id_seq")
	if err != nil {
		return nil, fmt.Errorf("error generating user ID: %w", err)
	}

	hashedPassword := hashPassword(req.Password)

	user := User{UserID: userID, Name: req.Name, Email: req.Email, Password: hashedPassword, CreatedAt: time.Now()}
	if err := auth.DB.Create(&user).Error; err != nil {
		return nil, fmt.Errorf("error inserting user: %w", err)
	}

	return &apex.SignupResponse{
		UserId: userID,
		Name:   req.Name,
		Email:  req.Email,
	}, nil
}

func (auth *AuthSvc) Login(ctx context.Context, req *apex.LoginRequest) (*apex.LoginResponse, error) {
	var user User
	result := auth.DB.Where("email = ?", req.Email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("invalid email or password")
		}
		return nil, fmt.Errorf("database error: %w", result.Error)
	}

	if hashPassword(req.Password) != user.Password {
		return nil, errors.New("invalid email or password")
	}

	var refreshToken Token
	auth.DB.Where("user_id = ? AND token_type = ?", user.UserID, "refresh").First(&refreshToken)

	if refreshToken.Token == "" || time.Now().After(refreshToken.TTL) {
		newRefreshToken, err := middleware.GenerateRefreshToken(user.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to generate refresh token: %w", err)
		}
		refreshToken = Token{UserID: user.UserID, TokenType: "refresh", Token: newRefreshToken, TTL: time.Now().Add(24 * time.Hour)}
		auth.DB.Save(&refreshToken)
	}

	accessToken, err := middleware.GenerateAccessToken(user.UserID, refreshToken.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	aToken := Token{UserID: user.UserID, TokenType: "access", Token: accessToken, TTL: time.Now().Add(15 * time.Minute)}
	auth.DB.Save(&aToken)
	auth.RedisClient.Set(ctx, fmt.Sprintf("accesstoken/%s", user.UserID), accessToken, 15*time.Minute)

	return &apex.LoginResponse{UserId: user.UserID, AccessToken: accessToken, RefreshToken: refreshToken.Token}, nil
}

func (auth *AuthSvc) Logout(ctx context.Context, userID *apex.LogoutRequest) (*apex.Empty, error) {
	auth.RedisClient.Del(ctx, fmt.Sprintf("accesstoken/%s", userID))
	return &apex.Empty{}, auth.DB.Where("user_id = ? AND token_type = ?", userID, "access").Delete(&Token{}).Error
}

func (auth *AuthSvc) getNextHexID(ctx context.Context, key string) (string, error) {
	nextID, err := auth.RedisClient.Incr(ctx, key).Result()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0x%x", nextID), nil
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}
