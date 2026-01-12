// Package repository provides data access layer implementations.
package repository

import (
	"context"
	"errors"
	"time"

	"github.com/cedev-1/template-go-auth/internal/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

func (r *refreshTokenRepository) RotateByToken(
	ctx context.Context,
	token string,
) (*domain.RefreshToken, error) {
	var rt domain.RefreshToken

	// Protection contre les races condition
	err := r.db.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("token = ?", token).
		First(&rt).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, domain.ErrRefreshTokenNotFound
		}
		return nil, err
	}

	if rt.Revoked {
		return &rt, domain.ErrTokenRevoked
	}

	// Protection contre les races condition
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&domain.RefreshToken{}).
		Where("id = ?", rt.ID).
		Where("revoked = ?", false). // Double-check
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		})

	if result.Error != nil {
		return nil, result.Error
	}

	if result.RowsAffected == 0 {
		return &rt, domain.ErrTokenRevoked
	}

	// Mettre à jour l'objet local
	rt.Revoked = true
	rt.RevokedAt = now

	return &rt, nil
}

// RevokeByToken revokes a specific refresh token.
func (r *refreshTokenRepository) RevokeByToken(
	ctx context.Context,
	token string,
) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&domain.RefreshToken{}).
		Where("token = ?", token).
		Where("revoked = ?", false).
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return domain.ErrRefreshTokenNotFound
	}

	return nil
}

// RevokeAllByUserID revokes all refresh tokens for a user.
func (r *refreshTokenRepository) RevokeAllByUserID(ctx context.Context, userID uint) error {
	now := time.Now()
	return r.db.WithContext(ctx).
		Model(&domain.RefreshToken{}).
		Where("user_id = ?", userID).
		Where("revoked = ?", false).
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		}).Error
}

// RevokeTokenFamily revokes all tokens in a token family (used for reuse detection).
func (r *refreshTokenRepository) RevokeTokenFamily(
	ctx context.Context,
	tokenFamily string,
) error {
	now := time.Now()

	// Update atomique de tous les tokens de la famille
	result := r.db.WithContext(ctx).
		Model(&domain.RefreshToken{}).
		Where("token_family = ?", tokenFamily).
		Where("revoked = ?", false).
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		})

	return result.Error
}

// GetActiveTokensByUser returns all active tokens for a user, ordered by creation date.
func (r *refreshTokenRepository) GetActiveTokensByUser(ctx context.Context, userID uint) ([]*domain.RefreshToken, error) {
	var tokens []*domain.RefreshToken
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Where("revoked = ?", false).
		Where("expires_at > ?", time.Now()).
		Order("created_at DESC").
		Find(&tokens).Error
	return tokens, err
}

// CountActiveTokensByUser returns the count of active tokens for a user.
func (r *refreshTokenRepository) CountActiveTokensByUser(ctx context.Context, userID uint) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&domain.RefreshToken{}).
		Where("user_id = ?", userID).
		Where("revoked = ?", false).
		Where("expires_at > ?", time.Now()).
		Count(&count).Error
	return count, err
}

// FindByTokenFamily returns all tokens in a token family.
func (r *refreshTokenRepository) FindByTokenFamily(ctx context.Context, tokenFamily string) ([]*domain.RefreshToken, error) {
	var tokens []*domain.RefreshToken
	err := r.db.WithContext(ctx).
		Where("token_family = ?", tokenFamily).
		Order("created_at ASC").
		Find(&tokens).Error
	return tokens, err
}

// DeleteExpired deletes all expired refresh tokens.
func (r *refreshTokenRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", time.Now()).
		Delete(&domain.RefreshToken{}).Error
}

// DeleteRevoked deletes revoked tokens older than the specified duration.
func (r *refreshTokenRepository) DeleteRevoked(ctx context.Context, olderThan time.Duration) error {
	cutoffTime := time.Now().Add(-olderThan)
	return r.db.WithContext(ctx).
		Where("revoked = ?", true).
		Where("revoked_at < ?", cutoffTime).
		Delete(&domain.RefreshToken{}).Error
}

// WithTransaction executes a function within a database transaction.
func (r *refreshTokenRepository) WithTransaction(ctx context.Context, fn func(RefreshTokenRepository) error) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		repo := &refreshTokenRepository{db: tx}
		return fn(repo)
	})
}
