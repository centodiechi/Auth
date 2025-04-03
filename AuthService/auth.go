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

type AuthSvc struct {
	apex.UnimplementedAuthServiceServer
	RedisClient *redis.Client
	DB          *gorm.DB
}

func (auth *AuthSvc) cacheUser(ctx context.Context, user *User) error {
	userData := map[string]interface{}{
		"user_id":  user.UserID,
		"name":     user.Name,
		"email":    user.Email,
		"password": user.Password,
	}

	key := fmt.Sprintf("user/%s", user.Email)
	return auth.RedisClient.HSet(ctx, key, userData).Err()
}

func (auth *AuthSvc) getUserFromCache(ctx context.Context, email string) (*User, error) {
	key := fmt.Sprintf("user/%s", email)
	userData, err := auth.RedisClient.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	if len(userData) == 0 {
		return nil, redis.Nil
	}

	return &User{
		UserID:   userData["user_id"],
		Name:     userData["name"],
		Email:    userData["email"],
		Password: userData["password"],
	}, nil
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

	auth.cacheUser(ctx, &user)

	return &apex.SignupResponse{
		UserId: userID,
		Name:   req.Name,
		Email:  req.Email,
	}, nil
}

func (auth *AuthSvc) Login(ctx context.Context, req *apex.LoginRequest) (*apex.LoginResponse, error) {
	user, err := auth.getUserFromCache(ctx, req.Email)

	if err == redis.Nil {
		user = &User{}
		result := auth.DB.Where("email = ?", req.Email).First(user)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				return nil, errors.New("invalid email or password")
			}
			return nil, fmt.Errorf("database error: %w", result.Error)
		}
		auth.cacheUser(ctx, user)
	} else if err != nil {
		return nil, fmt.Errorf("cache error: %w", err)
	}

	if hashPassword(req.Password) != user.Password {
		return nil, errors.New("invalid email or password")
	}

	accessToken, err := middleware.GenerateAccessToken(user.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &apex.LoginResponse{
		UserId:      user.UserID,
		AccessToken: accessToken,
	}, nil
}

func (auth *AuthSvc) Logout(ctx context.Context, req *apex.LogoutRequest) (*apex.Empty, error) {
	return &apex.Empty{}, nil
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
