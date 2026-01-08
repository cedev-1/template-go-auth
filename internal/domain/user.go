// Package domain contains the core business entities and errors.
package domain

import (
	"time"
)

// User represents a user in the system.
type User struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	Email        string    `json:"email" gorm:"uniqueIndex;not null"`
	PasswordHash string    `json:"-" gorm:"not null"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TableName specifies the table name for GORM.
func (User) TableName() string {
	return "users"
}
