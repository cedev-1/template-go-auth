// Package password provides password hashing utilities.
package password

import (
	"golang.org/x/crypto/bcrypt"
)

// DefaultCost is the default bcrypt cost.
const DefaultCost = 12

// Hasher provides password hashing functionality.
type Hasher interface {
	Hash(password string) (string, error)
	Check(password, hash string) bool
}

// bcryptHasher implements Hasher using bcrypt.
type bcryptHasher struct {
	cost int
}

// NewHasher creates a new password hasher.
func NewHasher() Hasher {
	return &bcryptHasher{cost: DefaultCost}
}

// NewHasherWithCost creates a new password hasher with custom cost.
func NewHasherWithCost(cost int) Hasher {
	return &bcryptHasher{cost: cost}
}

// Hash hashes a password using bcrypt.
func (h *bcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Check checks if a password matches a hash.
func (h *bcryptHasher) Check(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
