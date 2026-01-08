// Package domain contains the core business entities and errors.
package domain

import (
	"time"
)

// RefreshToken represents a refresh token stored in the database.
type RefreshToken struct {
	ID        uint      `json:"-" gorm:"primaryKey"`
	UserID    uint      `json:"-" gorm:"index;not null"`
	Token     string    `json:"-" gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `json:"-" gorm:"not null"`
	CreatedAt time.Time `json:"-"`
	Revoked   bool      `json:"-" gorm:"default:false"`
}

// TableName specifies the table name for GORM.
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

// IsExpired checks if the refresh token has expired.
func (r *RefreshToken) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// IsValid checks if the refresh token is valid (not expired and not revoked).
func (r *RefreshToken) IsValid() bool {
	return !r.Revoked && !r.IsExpired()
}
