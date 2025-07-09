package repo

import (
	"context"
	"database/sql"
	"github.com/drakond/module4-task1/pkg/logger"
)

type UserRepo struct {
	DB *sql.DB
}

func (r *UserRepo) UserExists(ctx context.Context, username string) (bool, error) {
	var exists bool
	err := r.DB.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE username=$1)", username).Scan(&exists)
	if err != nil {
		logger.Logger.Errorw("DB error in UserExists",
			"username", username,
			"error", err,
			"operation", "UserExists",
		)
	}
	return exists, err
}

func (r *UserRepo) CreateUser(ctx context.Context, username, hashedPassword, email string) error {
	_, err := r.DB.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3)`,
		username, hashedPassword, email,
	)
	if err != nil {
		logger.Logger.Errorw("DB error in CreateUser",
			"username", username,
			"error", err,
			"operation", "CreateUser",
		)
	}
	return err
}

func (r *UserRepo) GetUserForLogin(ctx context.Context, username string) (userID, hashedPassword string, err error) {
	err = r.DB.QueryRowContext(ctx,
		"SELECT id, password_hash FROM users WHERE username=$1",
		username,
	).Scan(&userID, &hashedPassword)
	if err != nil {
		logger.Logger.Errorw("DB error in GetUserForLogin",
			"username", username,
			"error", err,
			"operation", "GetUserForLogin",
		)
	}
	return
}
