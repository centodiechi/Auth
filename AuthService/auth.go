package authservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	middleware "github.com/centodiechi/Auth/jwtmiddleware"
	apex "github.com/centodiechi/Auth/protos/v1"

	redis "github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserRole string

const (
	RoleUser  UserRole = "USER"
	RoleAdmin UserRole = "ADMIN"
)

type User struct {
	UserID       string `gorm:"primaryKey"`
	Name         string
	Email        string `gorm:"unique"`
	Password     string
	Role         UserRole `gorm:"default:USER"`
	CreatedAt    time.Time
	RefreshToken string
}

type AuthSvc struct {
	apex.UnimplementedAuthServiceServer
	CacheClient *redis.Client
	SeqClient   *redis.Client
	DB          *gorm.DB
}

func (auth *AuthSvc) cacheUser(ctx context.Context, user *User) error {
	userData := map[string]string{
		"user_id":       user.UserID,
		"name":          user.Name,
		"email":         user.Email,
		"password":      user.Password,
		"role":          string(user.Role),
		"refresh_token": user.RefreshToken,
	}

	key := fmt.Sprintf("user/%s", user.Email)
	pipe := auth.CacheClient.TxPipeline()
	pipe.HSet(ctx, key, userData)
	pipe.Expire(ctx, key, time.Hour)

	_, err := pipe.Exec(ctx)
	return err
}

func (auth *AuthSvc) getUserFromCache(ctx context.Context, email string) (*User, error) {
	key := fmt.Sprintf("user/%s", email)
	userData, err := auth.CacheClient.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	if len(userData) == 0 {
		return nil, redis.Nil
	}

	return &User{
		UserID:       userData["user_id"],
		Name:         userData["name"],
		Email:        userData["email"],
		Password:     userData["password"],
		Role:         UserRole(userData["role"]),
		RefreshToken: userData["refresh_token"],
	}, nil
}

func hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

func comparePassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func (auth *AuthSvc) Signup(ctx context.Context, req *apex.SignupRequest) (*apex.SignupResponse, error) {
	var existingUser User
	result := auth.DB.Where("email = ?", req.Email).First(&existingUser)
	if result.Error == nil {
		return nil, errors.New("user already exists")
	} else if result.Error != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("error checking existing user: %w", result.Error)
	}

	userID, err := auth.GetNextHexID(ctx, "user_id_seq")
	if err != nil {
		return nil, fmt.Errorf("error generating user ID: %w", err)
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("error hashing password: %w", err)
	}

	role := RoleUser
	if req.Role != "" {
		role = UserRole(req.Role)
	}

	user := User{
		UserID:    userID,
		Name:      req.Name,
		Email:     req.Email,
		Password:  hashedPassword,
		Role:      role,
		CreatedAt: time.Now(),
	}

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

	if !comparePassword(user.Password, req.Password) {
		return nil, errors.New("invalid email or password")
	}

	accessToken, err := middleware.GenerateAccessToken(user.UserID, string(user.Role))
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := middleware.GenerateRefreshToken(user.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	user.RefreshToken = refreshToken
	if err := auth.DB.Save(user).Error; err != nil {
		return nil, fmt.Errorf("failed to update refresh token: %w", err)
	}

	auth.cacheUser(ctx, user)

	return &apex.LoginResponse{
		UserId:       user.UserID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (auth *AuthSvc) Logout(ctx context.Context, req *apex.LogoutRequest) (*apex.Empty, error) {
	var user User
	if err := auth.DB.Where("user_id = ?", req.UserId).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return &apex.Empty{}, nil
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	user.RefreshToken = ""
	if err := auth.DB.Save(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to invalidate refresh token: %w", err)
	}

	auth.cacheUser(ctx, &user)

	return &apex.Empty{}, nil
}

func (auth *AuthSvc) RefreshToken(ctx context.Context, req *apex.RefreshTokenRequest) (*apex.RefreshTokenResponse, error) {
	userID, err := middleware.VerifyRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	var user User
	if err := auth.DB.Where("user_id = ?", userID).First(&user).Error; err != nil {
		return nil, errors.New("user not found")
	}

	if user.RefreshToken != req.RefreshToken {
		return nil, errors.New("refresh token has been revoked")
	}

	accessToken, err := middleware.GenerateAccessToken(user.UserID, string(user.Role))
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &apex.RefreshTokenResponse{
		AccessToken: accessToken,
	}, nil
}

func (auth *AuthSvc) GetNextHexID(ctx context.Context, key string) (string, error) {
	nextID, err := auth.SeqClient.Incr(ctx, key).Result()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0x%x", nextID), nil
}
