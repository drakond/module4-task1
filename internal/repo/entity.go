package repo

import (
	"time"
)

type User struct {
	ID             int64
	Username       string
	HashedPassword string
	Email          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}