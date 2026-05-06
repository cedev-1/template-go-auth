// Package config provides configuration loading from environment variables.
package config

import (
	"io/ioutil"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the application.
type Config struct {
	Database         DatabaseConfig
	JWT              JWTConfig
	Server           ServerConfig
	Redis            RedisConfig
	RedisEnabled     bool
	JWTSyncWithRedis bool
}

// DatabaseConfig holds database configuration.
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
}

// JWTConfig holds JWT configuration.
type JWTConfig struct {
	Secret      string
	ExpiryHours int
}

// ServerConfig holds server configuration.
type ServerConfig struct {
	Port    string
	GinMode string
}

type YamlConfig struct {
	Redis            bool `yaml:"redis"`
	JWTSyncWithRedis bool `yaml:"jwt_sync_with_redis"`
}

var YamlConfigForCheck struct {
	RedisCheck            bool `yaml:"redis"`
	JWTSyncWithRedisCheck bool `yaml:"jwt_sync_with_redis"`
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	// Load .env file if it exists (ignore error if not found).
	_ = godotenv.Load()

	// Charger la configuration YAML
	yamlCfg := loadYamlConf()

	expiryHours, err := strconv.Atoi(getEnv("JWT_EXPIRY_HOURS", "24"))
	if err != nil {
		expiryHours = 24
	}

	redisPortStr := getEnv("REDIS_PORT", "6379")
	redisPort, err := strconv.Atoi(redisPortStr)
	if err != nil {
		redisPort = 6379
	}

	return &Config{
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			Port:     getEnv("DB_PORT", "5432"),
			User:     getEnv("DB_USER", "postgres"),
			Password: getEnv("DB_PASSWORD", "postgres"),
			Name:     getEnv("DB_NAME", "auth_db"),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Password: getEnv("REDIS_PASSWORD", "redis"),
			Port:     redisPort,
		},
		JWT: JWTConfig{
			Secret:      getEnv("JWT_SECRET", "default-secret-change-me"),
			ExpiryHours: expiryHours,
		},
		Server: ServerConfig{
			Port:    getEnv("SERVER_PORT", "8080"),
			GinMode: getEnv("GIN_MODE", "debug"),
		},
		RedisEnabled:     yamlCfg.Redis,
		JWTSyncWithRedis: yamlCfg.JWTSyncWithRedis,
	}, nil
}

// DSN returns the PostgreSQL connection string.
func (c *DatabaseConfig) DSN() string {
	return "host=" + c.Host +
		" user=" + c.User +
		" password=" + c.Password +
		" dbname=" + c.Name +
		" port=" + c.Port +
		" sslmode=disable TimeZone=UTC"
}

// loadYamlConf load the file config.yaml and returns the configuration
func loadYamlConf() YamlConfig {
	defaultCfg := YamlConfig{
		Redis:            false,
		JWTSyncWithRedis: false,
	}

	data, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Printf("Warning: config.yaml not found, using defaults: %v", err)
		return defaultCfg
	}

	// Parse the yaml configuration in the struct YamlConfig
	var yamlCfg YamlConfig
	err = yaml.Unmarshal(data, &yamlCfg)
	if err != nil {
		log.Printf("Error parsing config.yaml: %v", err)
		return defaultCfg
	}

	log.Printf("Configuration loaded: Redis=%v, JWT Sync with Redis=%v",
		yamlCfg.Redis, yamlCfg.JWTSyncWithRedis)

	return yamlCfg
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
