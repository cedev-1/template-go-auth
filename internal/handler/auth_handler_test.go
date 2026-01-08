package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cedev-1/template-go-auth/internal/domain"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuthService is a mock implementation of AuthService
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Register(ctx context.Context, email, password string) (*domain.User, error) {
	args := m.Called(ctx, email, password)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockAuthService) Login(ctx context.Context, email, password string) (string, error) {
	args := m.Called(ctx, email, password)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) GetUserByID(ctx context.Context, id uint) (*domain.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func setupRouter(handler *AuthHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/auth/register", handler.Register)
	router.POST("/auth/login", handler.Login)
	return router
}

func TestAuthHandler_Register_Success(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	email := "test@example.com"
	password := "password123"

	expectedUser := &domain.User{
		ID:    1,
		Email: email,
	}

	mockService.On("Register", mock.Anything, email, password).Return(expectedUser, nil)

	reqBody := RegisterRequest{
		Email:    email,
		Password: password,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var response UserResponse
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, uint(1), response.ID)
	assert.Equal(t, email, response.Email)

	mockService.AssertExpectations(t)
}

func TestAuthHandler_Register_ValidationError(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	// Invalid email
	reqBody := map[string]string{
		"email":    "invalid-email",
		"password": "password123",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthHandler_Register_PasswordTooShort(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	reqBody := map[string]string{
		"email":    "test@example.com",
		"password": "short",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestAuthHandler_Register_EmailAlreadyExists(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	email := "existing@example.com"
	password := "password123"

	mockService.On("Register", mock.Anything, email, password).Return(nil, domain.ErrEmailAlreadyExists)

	reqBody := RegisterRequest{
		Email:    email,
		Password: password,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)

	mockService.AssertExpectations(t)
}

func TestAuthHandler_Login_Success(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	email := "test@example.com"
	password := "password123"
	expectedToken := "jwt.token.here"

	mockService.On("Login", mock.Anything, email, password).Return(expectedToken, nil)

	reqBody := LoginRequest{
		Email:    email,
		Password: password,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.Equal(t, expectedToken, response["token"])

	mockService.AssertExpectations(t)
}

func TestAuthHandler_Login_InvalidCredentials(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	email := "test@example.com"
	password := "wrongpassword"

	mockService.On("Login", mock.Anything, email, password).Return("", domain.ErrInvalidCredentials)

	reqBody := LoginRequest{
		Email:    email,
		Password: password,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	mockService.AssertExpectations(t)
}

func TestAuthHandler_Login_ValidationError(t *testing.T) {
	mockService := new(MockAuthService)
	handler := NewAuthHandler(mockService)
	router := setupRouter(handler)

	// Missing password
	reqBody := map[string]string{
		"email": "test@example.com",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}
