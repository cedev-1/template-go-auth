package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cedev-1/template-go-auth/internal/domain"
	"github.com/redis/go-redis/v9"
)

const (
	SessionKeyPrefix      = "session"
	UserSessionsKeyPrefix = "user_sessions"
	JWTKeyPrefix          = "jwt"
)

type sessionRepository struct {
	client *redis.Client
}

func NewSessionRepository(client *redis.Client) SessionRepository {
	return &sessionRepository{client: client}
}

func (r *sessionRepository) sessionKey(userID uint, tokenFamily string) string {
	return fmt.Sprintf("%s:user:%d:%s", SessionKeyPrefix, userID, tokenFamily)
}

func (r *sessionRepository) userSessionsKey(userID uint) string {
	return fmt.Sprintf("%s:%d", UserSessionsKeyPrefix, userID)
}

func (r *sessionRepository) jwtKey(userID uint, tokenFamily string) string {
	return fmt.Sprintf("%s:user:%d:%s", JWTKeyPrefix, userID, tokenFamily)
}

func (r *sessionRepository) CreateSession(ctx context.Context, session *domain.Session) error {
	key := r.sessionKey(session.UserID, session.TokenFamily)
	userKey := r.userSessionsKey(session.UserID)

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return domain.ErrSessionExpired
	}

	pipe := r.client.Pipeline()

	pipe.Set(ctx, key, data, ttl)

	pipe.SAdd(ctx, userKey, session.TokenFamily)
	pipe.Expire(ctx, userKey, ttl)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

func (r *sessionRepository) GetSession(ctx context.Context, userID uint, tokenFamily string) (*domain.Session, error) {
	key := r.sessionKey(userID, tokenFamily)

	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, domain.ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session domain.Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

func (r *sessionRepository) UpdateSession(ctx context.Context, session *domain.Session) error {
	key := r.sessionKey(session.UserID, session.TokenFamily)

	// Check if session exists
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check session existence: %w", err)
	}
	if exists == 0 {
		return domain.ErrSessionNotFound
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return domain.ErrSessionExpired
	}

	if err := r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	return nil
}

func (r *sessionRepository) DeleteSession(ctx context.Context, userID uint, tokenFamily string) error {
	key := r.sessionKey(userID, tokenFamily)
	jwtKey := r.jwtKey(userID, tokenFamily)
	userKey := r.userSessionsKey(userID)

	pipe := r.client.Pipeline()
	pipe.Del(ctx, key)
	pipe.Del(ctx, jwtKey)
	pipe.SRem(ctx, userKey, tokenFamily)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

func (r *sessionRepository) DeleteAllUserSessions(ctx context.Context, userID uint) error {
	userKey := r.userSessionsKey(userID)

	tokenFamilies, err := r.client.SMembers(ctx, userKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil
		}
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	if len(tokenFamilies) == 0 {
		return nil
	}

	pipe := r.client.Pipeline()

	for _, tokenFamily := range tokenFamilies {
		sessionKey := r.sessionKey(userID, tokenFamily)
		jwtKey := r.jwtKey(userID, tokenFamily)
		pipe.Del(ctx, sessionKey)
		pipe.Del(ctx, jwtKey)
	}

	pipe.Del(ctx, userKey)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete all user sessions: %w", err)
	}

	return nil
}

func (r *sessionRepository) GetUserSessions(ctx context.Context, userID uint) ([]*domain.Session, error) {
	userKey := r.userSessionsKey(userID)

	tokenFamilies, err := r.client.SMembers(ctx, userKey).Result()
	if err != nil {
		if err == redis.Nil {
			return []*domain.Session{}, nil
		}
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	sessions := make([]*domain.Session, 0, len(tokenFamilies))
	expiredFamilies := make([]string, 0)

	for _, tokenFamily := range tokenFamilies {
		session, err := r.GetSession(ctx, userID, tokenFamily)
		if err != nil {
			if err == domain.ErrSessionNotFound {
				expiredFamilies = append(expiredFamilies, tokenFamily)
				continue
			}
			return nil, err
		}
		sessions = append(sessions, session)
	}

	if len(expiredFamilies) > 0 {
		pipe := r.client.Pipeline()
		for _, family := range expiredFamilies {
			pipe.SRem(ctx, userKey, family)
		}
		_, _ = pipe.Exec(ctx)
	}

	return sessions, nil
}

func (r *sessionRepository) SessionExists(ctx context.Context, userID uint, tokenFamily string) (bool, error) {
	key := r.sessionKey(userID, tokenFamily)

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check session existence: %w", err)
	}

	return exists > 0, nil
}

func (r *sessionRepository) StoreJWT(ctx context.Context, userID uint, tokenFamily string, accessToken string, expiry time.Duration) error {
	key := r.jwtKey(userID, tokenFamily)

	if err := r.client.Set(ctx, key, accessToken, expiry).Err(); err != nil {
		return fmt.Errorf("failed to store JWT: %w", err)
	}

	return nil
}

func (r *sessionRepository) ValidateJWT(ctx context.Context, userID uint, tokenFamily string) (bool, error) {
	key := r.jwtKey(userID, tokenFamily)

	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to validate JWT: %w", err)
	}

	return exists > 0, nil
}

func (r *sessionRepository) InvalidateJWT(ctx context.Context, userID uint, tokenFamily string) error {
	key := r.jwtKey(userID, tokenFamily)

	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to invalidate JWT: %w", err)
	}

	return nil
}

func (r *sessionRepository) RefreshSession(ctx context.Context, session *domain.Session, newAccessToken string, jwtExpiry time.Duration) error {
	pipe := r.client.Pipeline()

	//Update session
	sessionKey := r.sessionKey(session.UserID, session.TokenFamily)
	sessionData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	sessionTTL := time.Until(session.ExpiresAt)
	if sessionTTL <= 0 {
		return domain.ErrSessionExpired
	}

	pipe.Set(ctx, sessionKey, sessionData, sessionTTL)

	//gen new jwtKey in redis
	jwtKey := r.jwtKey(session.UserID, session.TokenFamily)
	pipe.Set(ctx, jwtKey, newAccessToken, jwtExpiry)

	_, err = pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to refresh session: %w", err)
	}

	return nil
}
