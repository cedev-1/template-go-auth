// Package service provides the business logic for authentication operations.
package service

import (
	"context"

	"github.com/cedev-1/template-go-auth/internal/domain"
)

// AuthService defines the interface for authentication operations.
type AuthService interface {
	Register(ctx context.Context, email, password string) (*domain.User, error)
	Login(ctx context.Context, email, password string) (*TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	LogoutAll(ctx context.Context, userID uint) error
	GetUserByID(ctx context.Context, id uint) (*domain.User, error)
}

// TokenPair contains access and refresh tokens.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
