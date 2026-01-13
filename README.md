# Go Auth Template

> **Version:** 1.1.0 | [Changelog](CHANGELOG.md)

Clean, production-ready authentication backend template built with Go, Gin, and Gorm.

## Use This Template

1. Click **"Use this template"** on GitHub
2. Clone your new repository
3. Update `go.mod` with your module name:
   ```bash
   go mod edit -module github.com/your-username/your-project
   ```
4. Find and replace `github.com/cedev-1/template-go-auth` with your module name
5. Run `task dev` to start developing

## Features

- User registration and login
- JWT authentication with refresh tokens
- Stateful token rotation and revocation
- Session management with active session listing and revocation
- Token family-based reuse detection
- Clean Architecture with dependency injection
- Unit and integration tests
- Docker & Docker Compose
- golangci-lint configuration
- Graceful shutdown

## Architecture

### Project Structure

```
template-go-auth/
├── cmd/server/              # Entry point
│   └── main.go
├── internal/
│   ├── config/              # Configuration
│   ├── container/           # Dependency injection container
│   ├── domain/              # Business entities & errors
│   ├── handler/             # HTTP handlers (= Controllers)
│   ├── middleware/          # Middleware (Auth, Error)
│   ├── repository/          # Data access layer
│   └── service/             # Business logic
├── pkg/
│   └── password/            # Utilities (hashing)
├── Taskfile.yml
├── Dockerfile
└── docker-compose.yml
```

### Application Layers

| Layer          | Responsibility                           | Depends on         |
| -------------- | ---------------------------------------- | ------------------ |
| **Handler**    | HTTP requests, validation, serialization | Service            |
| **Service**    | Business logic, orchestration, JWT       | Repository, Hasher |
| **Repository** | Data access, GORM                        | Domain             |
| **Domain**     | Entities, business errors                | ∅                  |

> **Note**: The term "Handler" in Go/Gin is equivalent to "Controller" in other frameworks (Spring, Laravel, etc.).

## Quick Start

```bash
# Start PostgreSQL
task db:up

# Run in development
task dev

# Run tests
task test

# Run linter
task lint
```

## API Endpoints

| Method | Endpoint                      | Description                  | Auth |
| ------ | ----------------------------- | ---------------------------- | ---- |
| POST   | /auth/register                | Create account               | No   |
| POST   | /auth/login                   | Login (returns tokens)       | No   |
| POST   | /auth/refresh                 | Refresh access token         | No   |
| POST   | /auth/logout                  | Revoke refresh token         | No   |
| POST   | /auth/logout-all              | Revoke all tokens            | Yes  |
| GET    | /auth/me                      | Get current user             | Yes  |
| POST   | /auth/session/revoke          | Revoke a specific session    | Yes  |
| GET    | /auth/session/active-sessions | Get all active sessions      | Yes  |
| GET    | /health                       | Health check                 | No   |

### Examples

```bash
# Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Login (returns access_token and refresh_token)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password123"}'

# Refresh token
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'

# Logout
curl -X POST http://localhost:8080/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<refresh_token>"}'

# Get current user (with access token)
curl http://localhost:8080/auth/me \
  -H "Authorization: Bearer <access_token>"

# Get active sessions
curl http://localhost:8080/auth/session/active-sessions \
  -H "Authorization: Bearer <access_token>"

# Revoke a specific session
curl -X POST http://localhost:8080/auth/session/revoke \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"session_id": 1}'
```

## Environment Variables

| Variable         | Default   | Description          |
| ---------------- | --------- | -------------------- |
| DB_HOST          | localhost | Database host        |
| DB_PORT          | 5432      | Database port        |
| DB_USER          | postgres  | Database user        |
| DB_PASSWORD      | postgres  | Database password    |
| DB_NAME          | auth_db   | Database name        |
| JWT_SECRET       | -         | JWT secret           |
| JWT_EXPIRY_HOURS | 24        | Token expiry (hours) |
| SERVER_PORT      | 8080      | Server port          |
| GIN_MODE         | debug     | `debug` or `release` |

## Task Commands

```bash
task dev            # Development mode
task build          # Build production binary
task run            # Run binary
task test           # Run tests
task test:coverage  # Tests + coverage
task lint           # Run golangci-lint
task lint:fix       # Auto-fix lint issues
task check          # fmt + vet + lint + test
task docker:build   # Build Docker image
task docker:run     # Run Docker container
task db:up          # Start PostgreSQL
task db:down        # Stop PostgreSQL
task db:reset       # Reset database
task ci             # Full CI pipeline
```

## Production

```bash
# Build and run
task build
GIN_MODE=release ./bin/auth-server

# Or via Docker
task docker:build
task docker:run
```

## License

[MIT](./LICENSE)
