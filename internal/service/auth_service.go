// Package service provides the business logic for authentication operations.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/cedev-1/template-go-auth/internal/config"
	"github.com/cedev-1/template-go-auth/internal/domain"
	"github.com/cedev-1/template-go-auth/internal/repository"
	"github.com/cedev-1/template-go-auth/pkg/password"
	"github.com/golang-jwt/jwt/v5"
)

const (
	RefreshTokenLength = 32
	RefreshTokenExpiryDays = 1
	MaxActiveTokensPerUser = 1
	TokenFamilyLength = 16
)

// authService implements AuthService.
type authService struct {
	userRepo         repository.UserRepository
	refreshTokenRepo repository.RefreshTokenRepository
	hasher           password.Hasher
	jwtCfg           config.JWTConfig
}

// SessionInfo represents information about an active session.
type SessionInfo struct {
	ID        uint      `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewAuthService creates a new AuthService instance.
func NewAuthService(
	userRepo repository.UserRepository,
	refreshTokenRepo repository.RefreshTokenRepository,
	hasher password.Hasher,
	jwtCfg config.JWTConfig,
) AuthService {
	return &authService{
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		hasher:           hasher,
		jwtCfg:           jwtCfg,
	}
}

func (s *authService) generateTokenPairWithFamily(
	ctx context.Context,
	user *domain.User,
	tokenFamily string,
	parentTokenID *uint,
) (*TokenPair, error) {

	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	refreshTokenEntity := &domain.RefreshToken{
		UserID:        user.ID,
		Token:         refreshToken,
		TokenFamily:   tokenFamily,
		ParentTokenID: parentTokenID,
		ExpiresAt:     time.Now().UTC().AddDate(0, 0, RefreshTokenExpiryDays),
	}

	if err := s.refreshTokenRepo.Create(ctx, refreshTokenEntity); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// Register creates a new user account.
func (s *authService) Register(ctx context.Context, email, pass string) (*domain.User, error) {
	// Check if user already exists.
	existing, err := s.userRepo.FindByEmail(ctx, email)
	if err == nil && existing != nil {
		return nil, domain.ErrEmailAlreadyExists
	}
	if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		return nil, err
	}

	// Hash the password.
	hashedPassword, err := s.hasher.Hash(pass)
	if err != nil {
		return nil, err
	}

	// Create the user.
	user := &domain.User{
		Email:        email,
		PasswordHash: hashedPassword,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// Login authenticates a user and returns a token pair.
// service/auth.go
func (s *authService) Login(ctx context.Context, email, pass string) (*TokenPair, error) {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, err
	}

	if !s.hasher.Check(pass, user.PasswordHash) {
		return nil, domain.ErrInvalidCredentials
	}

	// ✅ Utiliser une transaction pour garantir l'atomicité
	var pair *TokenPair
	err = s.refreshTokenRepo.WithTransaction(ctx, func(tx repository.RefreshTokenRepository) error {
		count, err := tx.CountActiveTokensByUser(ctx, user.ID)
		if err != nil {
			return err
		}

		if count >= MaxActiveTokensPerUser {
			tokens, err := tx.GetActiveTokensByUser(ctx, user.ID)
			if err != nil {
				return err
			}

			if len(tokens) > 0 {
				// Révoquer le plus ancien
				oldest := tokens[len(tokens)-1]
				if err := tx.RevokeByToken(ctx, oldest.Token); err != nil {
					return err
				}
			}
		}

		// Générer le nouveau token pair
		pair, err = s.generateTokenPair(ctx, user)
		return err
	})

	return pair, err
}

// Refresh exchanges a valid refresh token for a new token pair.
func (s *authService) Refresh(ctx context.Context, refreshToken string) (*TokenPair, error) {
	var pair *TokenPair

	err := s.refreshTokenRepo.WithTransaction(ctx, func(tx repository.RefreshTokenRepository) error {
		token, err := tx.RotateByToken(ctx, refreshToken)
		if err != nil {
			if errors.Is(err, domain.ErrTokenRevoked) {
				if token != nil && token.TokenFamily != "" {
					_ = tx.RevokeTokenFamily(ctx, token.TokenFamily)
				}
			}
			return err
		}

		if token.IsExpired() {
			_ = tx.RevokeTokenFamily(ctx, token.TokenFamily)
			return domain.ErrTokenExpired
		}

		user, err := s.userRepo.FindByID(ctx, token.UserID)
		if err != nil {
			return err
		}

		pair, err = s.generateTokenPairWithFamily(
			ctx,
			user,
			token.TokenFamily,
			&token.ID,
		)

		return err
	})

	return pair, err
}

// Logout revokes a refresh token.
func (s *authService) Logout(ctx context.Context, refreshToken string) error {
	return s.refreshTokenRepo.RevokeByToken(ctx, refreshToken)
}

// LogoutAll revokes all refresh tokens for a user.
func (s *authService) LogoutAll(ctx context.Context, userID uint) error {
	return s.refreshTokenRepo.RevokeAllByUserID(ctx, userID)
}

// GetUserByID retrieves a user by their ID.
func (s *authService) GetUserByID(ctx context.Context, id uint) (*domain.User, error) {
	return s.userRepo.FindByID(ctx, id)
}

func (s *authService) generateTokenPair(ctx context.Context, user *domain.User) (*TokenPair, error) {
	accessToken, err := s.generateAccessToken(user)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	familyBytes := make([]byte, TokenFamilyLength)
	if _, err := rand.Read(familyBytes); err != nil {
		return nil, err
	}
	tokenFamily := base64.RawURLEncoding.EncodeToString(familyBytes)

	entity := &domain.RefreshToken{
		UserID:      user.ID,
		Token:       refreshToken,
		TokenFamily: tokenFamily,
		ExpiresAt:   time.Now().UTC().AddDate(0, 0, RefreshTokenExpiryDays),
	}

	if err := s.refreshTokenRepo.Create(ctx, entity); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *authService) GetActiveSessions(ctx context.Context, userID uint) ([]*SessionInfo, error) {
	tokens, err := s.refreshTokenRepo.GetActiveTokensByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	sessions := make([]*SessionInfo, len(tokens))
	for i, token := range tokens {
		sessions[i] = &SessionInfo{
			ID:        token.ID,
			CreatedAt: token.CreatedAt,
			ExpiresAt: token.ExpiresAt,
		}
	}

	return sessions, nil
}

// RevokeSession revokes a specific session by token ID.
func (s *authService) RevokeSession(ctx context.Context, userID, tokenID uint) error {
	// Find the token to ensure it belongs to the user.
	tokens, err := s.refreshTokenRepo.GetActiveTokensByUser(ctx, userID)
	if err != nil {
		return err
	}

	for _, token := range tokens {
		if token.ID == tokenID {
			return s.refreshTokenRepo.RevokeByToken(ctx, token.Token)
		}
	}

	return domain.ErrRefreshTokenNotFound
}

// generateAccessToken creates a JWT access token for the user.
func (s *authService) generateAccessToken(user *domain.User) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Duration(s.jwtCfg.ExpiryHours) * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.jwtCfg.Secret))
}

// generateRefreshToken creates a secure random refresh token.
func (s *authService) generateRefreshToken() (string, error) {
	bytes := make([]byte, RefreshTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}
