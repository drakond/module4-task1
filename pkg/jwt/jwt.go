package jwt

import (
	"errors"
	"fmt"
	"github.com/drakond/module4-task1/internal/config"
	"github.com/drakond/module4-task1/pkg/logger"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

var jwtSecret []byte
var jwtIssuer string
var jwtLifetime time.Duration

func Init() error {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		logger.Logger.Errorw("JWT_SECRET environment variable not set")
		return fmt.Errorf("JWT_SECRET environment variable not set")
	}
	if len(secret) < 32 {
		logger.Logger.Errorw("JWT secret too short, must be at least 32 characters")
		return fmt.Errorf("JWT secret must be at least 32 characters long")
	}
	jwtSecret = []byte(secret)

	jwtIssuer = config.GetJWTIssuer()
	jwtLifetime = config.GetJWTLifetime()

	logger.Logger.Infow("JWT initialized",
		"issuer", jwtIssuer,
		"lifetime", jwtLifetime.String(),
	)

	return nil
}

func GenerateToken(userID string, username string) (string, error) {
	if len(jwtSecret) == 0 {
		logger.Logger.Errorw("JWT secret not initialized when generating token",
			"userID", userID,
			"username", username,
		)
		return "", errors.New("JWT secret not initialized")
	}

	claims := &Claims{
		UserID:   userID,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtLifetime)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    jwtIssuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSecret)
	if err != nil {
		logger.Logger.Errorw("Failed to sign JWT token",
			"userID", userID,
			"username", username,
			"error", err,
		)
		return "", err
	}
	logger.Logger.Infow("JWT token generated",
		"userID", userID,
		"username", username,
	)
	return signed, nil
}

func ValidateToken(tokenStr string) (*Claims, error) {
	if len(jwtSecret) == 0 {
		return nil, errors.New("JWT secret not initialized")
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		tokenStr,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("%w: %v", ErrUnexpectedSigningMethod, token.Header["alg"])
			}
			return jwtSecret, nil
		},
		jwt.WithLeeway(5*time.Second),
	)

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
