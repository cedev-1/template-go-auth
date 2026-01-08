// Package repository provides data access layer implementations.
package repository

import (
	"context"
	"errors"

	"github.com/cedev-1/template-go-auth/internal/domain"
	"gorm.io/gorm"
)

// refreshTokenRepository implements RefreshTokenRepository using GORM.
type refreshTokenRepository struct {
	db *gorm.DB
}

// NewRefreshTokenRepository creates a new RefreshTokenRepository instance.
func NewRefreshTokenRepository(db *gorm.DB) RefreshTokenRepository {
	return &refreshTokenRepository{db: db}
}

// Create creates a new refresh token in the database.
func (r *refreshTokenRepository) Create(ctx context.Context, token *domain.RefreshToken) error {
	return r.db.WithContext(ctx).Create(token).Error
}

// FindByToken finds a refresh token by its token string.
func (r *refreshTokenRepository) FindByToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	var refreshToken domain.RefreshToken
	result := r.db.WithContext(ctx).Where("token = ?", token).First(&refreshToken)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, domain.ErrRefreshTokenNotFound
		}
		return nil, result.Error
	}
	return &refreshToken, nil
}

// RevokeByToken revokes a refresh token by its token string.
func (r *refreshTokenRepository) RevokeByToken(ctx context.Context, token string) error {
	result := r.db.WithContext(ctx).
		Model(&domain.RefreshToken{}).
		Where("token = ?", token).
		Update("revoked", true)
	if result.RowsAffected == 0 {
		return domain.ErrRefreshTokenNotFound
	}
	return result.Error
}

// RevokeAllByUserID revokes all refresh tokens for a user.
func (r *refreshTokenRepository) RevokeAllByUserID(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).
		Model(&domain.RefreshToken{}).
		Where("user_id = ?", userID).
		Update("revoked", true).Error
}

// DeleteExpired deletes all expired refresh tokens.
func (r *refreshTokenRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < NOW()").
		Delete(&domain.RefreshToken{}).Error
}
