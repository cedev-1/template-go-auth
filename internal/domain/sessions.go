package domain

import (
	"errors"
	"time"
)

type Session struct {
	SessionID    string    `json:"session_id"`
	UserID       uint      `json:"user_id"`
	Email        string    `json:"email"`
	TokenFamily  string    `json:"token_family"`
	RefreshToken string    `json:"refresh_token"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)
