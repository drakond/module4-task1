package jwt

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
)

// Claims описывает payload токена
type Claims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Ошибки, связанные с JWT
var (
	ErrInvalidToken            = errors.New("invalid token")
	ErrUnexpectedSigningMethod = errors.New("unexpected signing method")
)
