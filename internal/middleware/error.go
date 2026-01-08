// Package middleware provides HTTP middleware for the Gin router.
package middleware

import (
	"errors"
	"net/http"

	"github.com/cedev-1/template-go-auth/internal/domain"
	"github.com/gin-gonic/gin"
)

// ErrorResponse represents an error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}

// ErrorHandler is a middleware that handles errors set by handlers.
func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		// Check if there are any errors.
		if len(c.Errors) > 0 {
			err := c.Errors.Last().Err
			handleError(c, err)
		}
	}
}

// handleError maps domain errors to HTTP responses.
func handleError(c *gin.Context, err error) {
	var statusCode int
	var message string

	switch {
	case errors.Is(err, domain.ErrUserNotFound):
		statusCode = http.StatusNotFound
		message = "user not found"
	case errors.Is(err, domain.ErrEmailAlreadyExists):
		statusCode = http.StatusConflict
		message = "email already exists"
	case errors.Is(err, domain.ErrInvalidCredentials):
		statusCode = http.StatusUnauthorized
		message = "invalid credentials"
	case errors.Is(err, domain.ErrInvalidToken):
		statusCode = http.StatusUnauthorized
		message = "invalid token"
	case errors.Is(err, domain.ErrTokenExpired):
		statusCode = http.StatusUnauthorized
		message = "token expired"
	default:
		statusCode = http.StatusInternalServerError
		message = "internal server error"
	}

	c.JSON(statusCode, ErrorResponse{
		Error: message,
	})
}
