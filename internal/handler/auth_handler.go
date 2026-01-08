// Package handler provides HTTP handlers for the API endpoints.
package handler

import (
	"errors"
	"net/http"

	"github.com/cedev-1/template-go-auth/internal/domain"
	"github.com/cedev-1/template-go-auth/internal/middleware"
	"github.com/cedev-1/template-go-auth/internal/service"
	"github.com/gin-gonic/gin"
)

// AuthHandler handles authentication HTTP requests.
type AuthHandler struct {
	authService service.AuthService
}

// NewAuthHandler creates a new AuthHandler instance.
func NewAuthHandler(authService service.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: authService,
	}
}

// RegisterRequest represents a registration request.
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

// LoginRequest represents a login request.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// RefreshRequest represents a token refresh request.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutRequest represents a logout request.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// UserResponse represents a user response.
type UserResponse struct {
	ID    uint   `json:"id"`
	Email string `json:"email"`
}

// TokenResponse represents a login/refresh response with tokens.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Register handles user registration.
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation error",
			"details": err.Error(),
		})
		return
	}

	user, err := h.authService.Register(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, domain.ErrEmailAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{
				"error": "email already exists",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create user",
		})
		return
	}

	c.JSON(http.StatusCreated, UserResponse{
		ID:    user.ID,
		Email: user.Email,
	})
}

// Login handles user login.
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation error",
			"details": err.Error(),
		})
		return
	}

	tokenPair, err := h.authService.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid credentials",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to login",
		})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
}

// Refresh handles token refresh.
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation error",
			"details": err.Error(),
		})
		return
	}

	tokenPair, err := h.authService.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRefreshTokenNotFound):
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid refresh token",
			})
		case errors.Is(err, domain.ErrTokenRevoked):
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "token has been revoked",
			})
		case errors.Is(err, domain.ErrTokenExpired):
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "token has expired",
			})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to refresh token",
			})
		}
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  tokenPair.AccessToken,
		RefreshToken: tokenPair.RefreshToken,
	})
}

// Logout handles user logout (revokes refresh token).
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "validation error",
			"details": err.Error(),
		})
		return
	}

	if err := h.authService.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		if errors.Is(err, domain.ErrRefreshTokenNotFound) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid refresh token",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to logout",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "logged out successfully",
	})
}

// LogoutAll handles logout from all devices (revokes all refresh tokens).
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
		})
		return
	}

	if err := h.authService.LogoutAll(c.Request.Context(), userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to logout from all devices",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "logged out from all devices",
	})
}

// Me returns the current authenticated user.
func (h *AuthHandler) Me(c *gin.Context) {
	userID, ok := middleware.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
		})
		return
	}

	user, err := h.authService.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "user not found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get user",
		})
		return
	}

	c.JSON(http.StatusOK, UserResponse{
		ID:    user.ID,
		Email: user.Email,
	})
}
