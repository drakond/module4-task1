package config

import (
	"fmt"
	"github.com/drakond/module4-task1/pkg/logger"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Warning: .env file not found, using system environment variables")
	}
}

func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	logger.Logger.Infow("Env variable not set, using default",
		"key", key,
		"default", defaultValue,
	)
	return defaultValue
}

func BuildDSN() string {
	host := GetEnv("DB_HOST", "localhost")
	port := GetEnv("DB_PORT", "5432")
	user := GetEnv("DB_USER", "user")
	password := GetEnv("DB_PASSWORD", "password")
	dbname := GetEnv("DB_NAME", "module4-task1")
	sslmode := GetEnv("DB_SSLMODE", "disable")

	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)
}

// GetJWTIssuer возвращает issuer для JWT из переменной окружения или дефолтное значение
func GetJWTIssuer() string {
	return GetEnv("JWT_ISSUER", "my-app")
}

// GetJWTLifetime возвращает lifetime для JWT в формате time.Duration (минуты)
func GetJWTLifetime() time.Duration {
	minutesStr := GetEnv("JWT_LIFETIME", "60")
	minutes, err := strconv.Atoi(minutesStr)
	if err != nil || minutes <= 0 {
		logger.Logger.Errorw("Invalid JWT_LIFETIME value, using default 60",
			"value", minutesStr,
			"error", err,
		)
		minutes = 60
	}
	return time.Duration(minutes) * time.Minute
}
