package authservice

import (
	apex "auth/protos/v1"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

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

	accessToken, err := GenerateToken(user.UserID, "access", 15)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %v", err)
	}

	refreshToken, err := auth.RedisClient.Get(ctx, "refresh_token/"+user.UserID).Result()
	if err == redis.Nil {
		var refreshTokenData Token
		if err := auth.DB.Where("user_id = ? AND token_type = ?", user.UserID, "refresh").First(&refreshTokenData).Error; err == nil {
			refreshToken = refreshTokenData.Token
			auth.RedisClient.Set(ctx, "refresh_token/"+user.UserID, refreshToken, time.Until(refreshTokenData.TTL))
		} else {
			refreshToken, err = GenerateToken(user.UserID, "refresh", 7*24*60)
			if err != nil {
				return nil, fmt.Errorf("failed to generate refresh token: %v", err)
			}

			refreshTokenData := Token{
				UserID:    user.UserID,
				TokenType: "refresh",
				Token:     refreshToken,
				CreatedAt: time.Now(),
				TTL:       time.Now().Add(7 * 24 * time.Hour),
			}
			if err := auth.DB.Create(&refreshTokenData).Error; err != nil {
				return nil, fmt.Errorf("failed to store refresh token in database: %v", err)
			}

			auth.RedisClient.Set(ctx, "refresh_token/"+user.UserID, refreshToken, 7*24*time.Hour)
		}
	}

	auth.RedisClient.Set(ctx, "access_token/"+user.UserID, accessToken, 15*time.Minute)

	return &apex.LoginResponse{
		UserId:       user.UserID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (auth *AuthSvc) RefreshToken(ctx context.Context, req *apex.RefreshTokenRequest) (*apex.RefreshTokenResponse, error) {
	userID, err := Verify_(req.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	storedToken, err := auth.RedisClient.Get(ctx, "refresh_token/"+userID).Result()
	if err != nil || storedToken != req.RefreshToken {
		return nil, errors.New("refresh token not found or expired")
	}

	newAccessToken, err := GenerateToken(userID, "access", 15)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	auth.RedisClient.Set(ctx, "access_token/"+userID, newAccessToken, 15*time.Minute)

	return &apex.RefreshTokenResponse{
		AccessToken: newAccessToken,
	}, nil
}

func (auth *AuthSvc) VerifyToken(ctx context.Context, req *apex.VerifyTokenRequest) (*apex.VerifyTokenResponse, error) {
	userID, err := Verify_(req.Token)
	if err != nil {
		return &apex.VerifyTokenResponse{Valid: false}, err
	}

	return &apex.VerifyTokenResponse{
		Valid:  true,
		UserId: userID,
	}, nil
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
