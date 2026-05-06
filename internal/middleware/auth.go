// Package middleware provides HTTP middleware for the Gin router.
package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/cedev-1/template-go-auth/internal/config"
	"github.com/cedev-1/template-go-auth/internal/repository"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// AuthMiddlewareConfig holds the configuration for the auth middleware.
type AuthMiddlewareConfig struct {
	JWTConfig        config.JWTConfig
	SessionRepo      repository.SessionRepository
	RedisEnabled     bool
	JWTSyncWithRedis bool
}

// AuthMiddleware creates a JWT authentication middleware.
func AuthMiddleware(jwtCfg config.JWTConfig) gin.HandlerFunc {
	return AuthMiddlewareWithConfig(AuthMiddlewareConfig{
		JWTConfig:        jwtCfg,
		SessionRepo:      nil,
		RedisEnabled:     false,
		JWTSyncWithRedis: false,
	})
}

// AuthMiddlewareWithConfig creates a JWT authentication middleware with Redis session validation.
func AuthMiddlewareWithConfig(cfg AuthMiddlewareConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "authorization header required",
			})
			return
		}

		// Extract token from "Bearer <token>".
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format",
			})
			return
		}

		tokenString := parts[1]

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return []byte(cfg.JWTConfig.Secret), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or expired token",
			})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token claims",
			})
			return
		}

		userIDRaw, ok := claims["user_id"]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid user_id claim",
			})
			return
		}
		userID, ok := userIDRaw.(float64)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid user_id type",
			})
			return
		}

		email, ok := claims["email"]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing email claim",
			})
			return
		}

		if _, ok := claims["exp"]; !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid exp claim",
			})
			return
		}

		if _, ok := claims["iat"]; !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid iat claim",
			})
			return
		}

		tokenFamily, _ := claims["token_family"].(string)

		//Check Redis and active session
		if cfg.RedisEnabled && cfg.JWTSyncWithRedis && cfg.SessionRepo != nil {
			if tokenFamily == "" {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "missing token_family claim",
				})
				return
			}
			ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
			defer cancel()

			exists, err := cfg.SessionRepo.SessionExists(ctx, uint(userID), tokenFamily)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": "failed to validate session",
				})
				return
			}

			if !exists {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
					"error": "session has been revoked",
				})
				return
			}
		}

		c.Set("user_id", uint(userID))
		c.Set("email", email)
		c.Set("exp", claims["exp"])
		c.Set("iat", claims["iat"])
		if tokenFamily != "" {
			c.Set("token_family", tokenFamily)
		}

		c.Next()
	}
}

// GetTokenFamily extracts the token family from the gin context.
func GetTokenFamily(c *gin.Context) (string, bool) {
	tokenFamily, exists := c.Get("token_family")
	if !exists {
		return "", false
	}
	family, ok := tokenFamily.(string)
	return family, ok
}

// GetUserID extracts the user ID from the gin context.
func GetUserID(c *gin.Context) (uint, bool) {
	userID, exists := c.Get("user_id")
	if !exists {
		return 0, false
	}
	id, ok := userID.(uint)
	return id, ok
}
