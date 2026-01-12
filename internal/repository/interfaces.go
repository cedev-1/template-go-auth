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
	// Create creates a new refresh token in the database.
	Create(ctx context.Context, token *domain.RefreshToken) error

	// RotateByToken atomically revokes a token and returns its data (replaces FindByToken for security).
	RotateByToken(ctx context.Context, token string) (*domain.RefreshToken, error)

	// RevokeByToken revokes a specific refresh token.
	RevokeByToken(ctx context.Context, token string) error

	// RevokeAllByUserID revokes all refresh tokens for a user.
	RevokeAllByUserID(ctx context.Context, userID uint) error

	// RevokeTokenFamily revokes all tokens in a token family (for reuse detection).
	RevokeTokenFamily(ctx context.Context, tokenFamily string) error

	// GetActiveTokensByUser returns all active tokens for a user.
	GetActiveTokensByUser(ctx context.Context, userID uint) ([]*domain.RefreshToken, error)

	// CountActiveTokensByUser returns the count of active tokens for a user.
	CountActiveTokensByUser(ctx context.Context, userID uint) (int64, error)

	// FindByTokenFamily returns all tokens in a token family.
	FindByTokenFamily(ctx context.Context, tokenFamily string) ([]*domain.RefreshToken, error)

	// DeleteExpired deletes all expired refresh tokens.
	DeleteExpired(ctx context.Context) error

	// DeleteRevoked deletes revoked tokens older than the specified duration.
	DeleteRevoked(ctx context.Context, olderThan time.Duration) error

	// WithTransaction executes a function within a database transaction.
	WithTransaction(ctx context.Context, fn func(RefreshTokenRepository) error) error
}
