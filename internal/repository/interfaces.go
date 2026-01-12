// Package repository provides data access layer implementations.
package repository

import (
	"context"
	"time"

	"github.com/cedev-1/template-go-auth/internal/domain"
)

// UserRepository defines the interface for user data access.
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	FindByID(ctx context.Context, id uint) (*domain.User, error)
}

// RefreshTokenRepository defines the interface for refresh token data access.
type RefreshTokenRepository interface {
	Create(ctx context.Context, token *domain.RefreshToken) error
	RotateByToken(ctx context.Context, token string) (*domain.RefreshToken, error)
	RevokeByToken(ctx context.Context, token string) error
	RevokeAllByUserID(ctx context.Context, userID uint) error
	RevokeTokenFamily(ctx context.Context, tokenFamily string) error
	GetActiveTokensByUser(ctx context.Context, userID uint) ([]*domain.RefreshToken, error)
	CountActiveTokensByUser(ctx context.Context, userID uint) (int64, error)
	FindByTokenFamily(ctx context.Context, tokenFamily string) ([]*domain.RefreshToken, error)
	DeleteExpired(ctx context.Context) error
	DeleteRevoked(ctx context.Context, olderThan time.Duration) error
	WithTransaction(ctx context.Context, fn func(RefreshTokenRepository) error) error
}
