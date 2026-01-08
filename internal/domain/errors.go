// Package domain contains the core business entities and errors.
package domain

import "errors"

// Domain errors.
var (
	ErrUserNotFound         = errors.New("user not found")
	ErrEmailAlreadyExists   = errors.New("email already exists")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrInvalidToken         = errors.New("invalid token")
	ErrTokenExpired         = errors.New("token expired")
	ErrTokenRevoked         = errors.New("token revoked")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
)
