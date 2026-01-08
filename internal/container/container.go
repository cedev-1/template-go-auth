// Package container provides the dependency injection container.
package container

import (
	"fmt"
	"log"

	"github.com/cedev-1/template-go-auth/internal/config"
	"github.com/cedev-1/template-go-auth/internal/domain"
	"github.com/cedev-1/template-go-auth/internal/handler"
	"github.com/cedev-1/template-go-auth/internal/middleware"
	"github.com/cedev-1/template-go-auth/internal/repository"
	"github.com/cedev-1/template-go-auth/internal/service"
	"github.com/cedev-1/template-go-auth/pkg/password"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Container holds all application dependencies.
type Container struct {
	Config      *config.Config
	DB          *gorm.DB
	Router      *gin.Engine
	AuthHandler *handler.AuthHandler
}

// New creates a new dependency injection container.
func New(cfg *config.Config) (*Container, error) {
	container := &Container{
		Config: cfg,
	}

	// Initialize database.
	if err := container.initDatabase(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize all dependencies.
	container.initDependencies()

	return container, nil
}

// initDatabase initializes the database connection and runs migrations.
func (c *Container) initDatabase() error {
	// Configure GORM logger.
	gormLogger := logger.Default.LogMode(logger.Silent)
	if c.Config.Server.GinMode == "debug" {
		gormLogger = logger.Default.LogMode(logger.Info)
	}

	// Connect to database.
	db, err := gorm.Open(postgres.Open(c.Config.Database.DSN()), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations.
	if err := db.AutoMigrate(&domain.User{}, &domain.RefreshToken{}); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	c.DB = db
	log.Println("Database connected and migrations completed")
	return nil
}

// initDependencies wires up all application dependencies.
func (c *Container) initDependencies() {
	// Set Gin mode.
	gin.SetMode(c.Config.Server.GinMode)

	// Create repositories.
	userRepo := repository.NewUserRepository(c.DB)
	refreshTokenRepo := repository.NewRefreshTokenRepository(c.DB)

	// Create utilities.
	hasher := password.NewHasher()

	// Create services.
	authService := service.NewAuthService(userRepo, refreshTokenRepo, hasher, c.Config.JWT)

	// Create handlers.
	c.AuthHandler = handler.NewAuthHandler(authService)

	// Setup router.
	c.Router = c.setupRouter()
}

// setupRouter configures the Gin router with all routes.
func (c *Container) setupRouter() *gin.Engine {
	router := gin.New()

	// Global middleware.
	router.Use(gin.Recovery())
	router.Use(gin.Logger())
	router.Use(middleware.ErrorHandler())

	// Health check.
	router.GET("/health", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"status": "ok"})
	})

	// Auth routes (public).
	auth := router.Group("/auth")
	{
		auth.POST("/register", c.AuthHandler.Register)
		auth.POST("/login", c.AuthHandler.Login)
		auth.POST("/refresh", c.AuthHandler.Refresh)
		auth.POST("/logout", c.AuthHandler.Logout)
	}

	// Protected routes.
	protected := router.Group("/auth")
	protected.Use(middleware.AuthMiddleware(c.Config.JWT))
	{
		protected.GET("/me", c.AuthHandler.Me)
		protected.POST("/logout-all", c.AuthHandler.LogoutAll)
	}

	return router
}

// Close closes all resources.
func (c *Container) Close() error {
	sqlDB, err := c.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
