package service

import (
	"context"
	"testing"

	"github.com/cedev-1/template-go-auth/internal/config"
	"github.com/cedev-1/template-go-auth/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id uint) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

// MockHasher is a mock implementation of password.Hasher
type MockHasher struct {
	mock.Mock
}

func (m *MockHasher) Hash(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockHasher) Check(password, hash string) bool {
	args := m.Called(password, hash)
	return args.Bool(0)
}

func TestAuthService_Register_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockHasher := new(MockHasher)
	jwtCfg := config.JWTConfig{Secret: "test-secret", ExpiryHours: 24}

	service := NewAuthService(mockRepo, mockHasher, jwtCfg)

	ctx := context.Background()
	email := "test@example.com"
	password := "password123"
	hashedPassword := "hashed_password"

	// Setup expectations
	mockRepo.On("FindByEmail", ctx, email).Return(nil, domain.ErrUserNotFound)
	mockHasher.On("Hash", password).Return(hashedPassword, nil)
	mockRepo.On("Create", ctx, mock.AnythingOfType("*domain.User")).Return(nil)

	// Execute
	user, err := service.Register(ctx, email, password)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, email, user.Email)
	assert.Equal(t, hashedPassword, user.PasswordHash)

	mockRepo.AssertExpectations(t)
	mockHasher.AssertExpectations(t)
}

func TestAuthService_Register_EmailAlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockHasher := new(MockHasher)
	jwtCfg := config.JWTConfig{Secret: "test-secret", ExpiryHours: 24}

	service := NewAuthService(mockRepo, mockHasher, jwtCfg)

	ctx := context.Background()
	email := "existing@example.com"
	password := "password123"

	existingUser := &domain.User{ID: 1, Email: email}

	// Setup expectations
	mockRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)

	// Execute
	user, err := service.Register(ctx, email, password)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domain.ErrEmailAlreadyExists, err)
	assert.Nil(t, user)

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockHasher := new(MockHasher)
	jwtCfg := config.JWTConfig{Secret: "test-secret", ExpiryHours: 24}

	service := NewAuthService(mockRepo, mockHasher, jwtCfg)

	ctx := context.Background()
	email := "test@example.com"
	password := "password123"
	hashedPassword := "hashed_password"

	existingUser := &domain.User{
		ID:           1,
		Email:        email,
		PasswordHash: hashedPassword,
	}

	// Setup expectations
	mockRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)
	mockHasher.On("Check", password, hashedPassword).Return(true)

	// Execute
	token, err := service.Login(ctx, email, password)

	// Assert
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	mockRepo.AssertExpectations(t)
	mockHasher.AssertExpectations(t)
}

func TestAuthService_Login_InvalidCredentials_WrongPassword(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockHasher := new(MockHasher)
	jwtCfg := config.JWTConfig{Secret: "test-secret", ExpiryHours: 24}

	service := NewAuthService(mockRepo, mockHasher, jwtCfg)

	ctx := context.Background()
	email := "test@example.com"
	password := "wrongpassword"
	hashedPassword := "hashed_password"

	existingUser := &domain.User{
		ID:           1,
		Email:        email,
		PasswordHash: hashedPassword,
	}

	// Setup expectations
	mockRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)
	mockHasher.On("Check", password, hashedPassword).Return(false)

	// Execute
	token, err := service.Login(ctx, email, password)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Empty(t, token)

	mockRepo.AssertExpectations(t)
	mockHasher.AssertExpectations(t)
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockHasher := new(MockHasher)
	jwtCfg := config.JWTConfig{Secret: "test-secret", ExpiryHours: 24}

	service := NewAuthService(mockRepo, mockHasher, jwtCfg)

	ctx := context.Background()
	email := "nonexistent@example.com"
	password := "password123"

	// Setup expectations
	mockRepo.On("FindByEmail", ctx, email).Return(nil, domain.ErrUserNotFound)

	// Execute
	token, err := service.Login(ctx, email, password)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domain.ErrInvalidCredentials, err)
	assert.Empty(t, token)

	mockRepo.AssertExpectations(t)
}

func TestAuthService_GetUserByID_Success(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockHasher := new(MockHasher)
	jwtCfg := config.JWTConfig{Secret: "test-secret", ExpiryHours: 24}

	service := NewAuthService(mockRepo, mockHasher, jwtCfg)

	ctx := context.Background()
	userID := uint(1)

	expectedUser := &domain.User{
		ID:    userID,
		Email: "test@example.com",
	}

	// Setup expectations
	mockRepo.On("FindByID", ctx, userID).Return(expectedUser, nil)

	// Execute
	user, err := service.GetUserByID(ctx, userID)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, expectedUser.ID, user.ID)
	assert.Equal(t, expectedUser.Email, user.Email)

	mockRepo.AssertExpectations(t)
}

func TestAuthService_GetUserByID_NotFound(t *testing.T) {
	mockRepo := new(MockUserRepository)
	mockHasher := new(MockHasher)
	jwtCfg := config.JWTConfig{Secret: "test-secret", ExpiryHours: 24}

	service := NewAuthService(mockRepo, mockHasher, jwtCfg)

	ctx := context.Background()
	userID := uint(999)

	// Setup expectations
	mockRepo.On("FindByID", ctx, userID).Return(nil, domain.ErrUserNotFound)

	// Execute
	user, err := service.GetUserByID(ctx, userID)

	// Assert
	assert.Error(t, err)
	assert.Equal(t, domain.ErrUserNotFound, err)
	assert.Nil(t, user)

	mockRepo.AssertExpectations(t)
}
