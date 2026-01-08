// Package service provides the business logic for authentication operations.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/cedev-1/template-go-auth/internal/config"
	"github.com/cedev-1/template-go-auth/internal/domain"
	"github.com/cedev-1/template-go-auth/internal/repository"
	"github.com/cedev-1/template-go-auth/pkg/password"
	"github.com/golang-jwt/jwt/v5"
)

const (
	// RefreshTokenLength is the length of the refresh token in bytes.
	RefreshTokenLength = 32
	// RefreshTokenExpiryDays is the default refresh token expiry in days.
	RefreshTokenExpiryDays = 30
)

// authService implements AuthService.
type authService struct {
	userRepo         repository.UserRepository
	refreshTokenRepo repository.RefreshTokenRepository
	hasher           password.Hasher
	jwtCfg           config.JWTConfig
}

// NewAuthService creates a new AuthService instance.
func NewAuthService(
	userRepo repository.UserRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	hasher password.Hasher,
	jwtCfg config.JWTConfig,
) AuthService {
	return &authService{
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		hasher:           hasher,
		jwtCfg:           jwtCfg,
	}
}

// Register creates a new user account.
func (s *authService) Register(ctx context.Context, email, pass string) (*domain.User, error) {
	// Check if user already exists.
	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err == nil && existing != nil {
		return nil, domain.ErrEmailAlreadyExists
	}
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		return nil, err
	}

	// Hash the password.
	hashedPassword, err := s.hasher.Hash(pass)
	if err != nil {
		return nil, err
	}

	// Create the user.
	user := &domain.User{
		Email:        email,
		PasswordHash: hashedPassword,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// Login authenticates a user and returns a token pair.
func (s *authService) Login(ctx context.Context, email, pass string) (*TokenPair, error) {
	// Find the user.
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	// Check the password.
	if !s.hasher.Check(pass, user.PasswordHash) {
		return nil, domain.ErrInvalidCredentials
	}

	// Generate token pair.
	return s.generateTokenPair(ctx, user)
}

// Refresh exchanges a valid refresh token for a new token pair.
func (s *authService) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Find the refresh token.
	token, err := s.refreshTokenRepo.FindByToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	// Check if token is valid.
	if token.Revoked {
		return nil, domain.ErrTokenRevoked
	}
	if token.IsExpired() {
		return nil, domain.ErrTokenExpired
	}

	// Revoke the old refresh token (rotation).
	if err := s.refreshTokenRepo.RevokeByToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	// Get the user.
	user, err := s.userRepo.FindByID(ctx, token.UserID)
	if err != nil {
		return nil, err
	}

	// Generate new token pair.
	return s.generateTokenPair(ctx, user)
}

// Logout revokes a refresh token.
func (s *authService) Logout(ctx context.Context, refreshToken string) error {
	return s.refreshTokenRepo.RevokeByToken(ctx, refreshToken)
}

// LogoutAll revokes all refresh tokens for a user.
func (s *authService) LogoutAll(ctx context.Context, userID uint) error {
	return s.refreshTokenRepo.RevokeAllByUserID(ctx, userID)
}

// GetUserByID retrieves a user by their ID.
func (s *authService) GetUserByID(ctx context.Context, id uint) (*domain.User, error) {
	return s.userRepo.FindByID(ctx, id)
}

// generateTokenPair creates an access token and refresh token for the user.
func (s *authService) generateTokenPair(ctx context.Context, user *domain.User) (*TokenPair, error) {
	// Generate access token.
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	// Generate refresh token.
	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Store refresh token in database.
	refreshTokenEntity := &domain.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().AddDate(0, 0, RefreshTokenExpiryDays),
	}
	if err := s.refreshTokenRepo.Create(ctx, refreshTokenEntity); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// generateAccessToken creates a JWT access token for the user.
func (s *authService) generateAccessToken(user *domain.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Duration(s.jwtCfg.ExpiryHours) * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtCfg.Secret))
}

// generateRefreshToken creates a secure random refresh token.
func (s *authService) generateRefreshToken() (string, error) {
	bytes := make([]byte, RefreshTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
