package service

import (
	"context"
	"github.com/drakond/module4-task1/grpc/genproto"
	"github.com/drakond/module4-task1/internal/repo"
	"github.com/drakond/module4-task1/pkg/jwt"
	"github.com/drakond/module4-task1/pkg/logger"
	"time"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthService struct {
	Repo *repo.UserRepo
	genproto.UnimplementedAuthServiceServer
}

func (s *AuthService) Register(ctx context.Context, req *genproto.RegisterRequest) (*genproto.RegisterResponse, error) {
	ctxDB, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	exists, err := s.Repo.UserExists(ctxDB, req.Username)
	if err != nil {
		logger.Logger.Errorw("DB error during user existence check",
			"username", req.Username,
			"error", err,
			"operation", "register",
		)
		return nil, status.Errorf(codes.Internal, "DB error: %v", err)
	}
	if exists {
		logger.Logger.Infow("User already exists",
			"username", req.Username,
			"operation", "register",
		)
		return nil, status.Errorf(codes.AlreadyExists, "user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Logger.Errorw("Password hash error",
			"username", req.Username,
			"error", err,
			"operation", "register",
		)
		return nil, status.Errorf(codes.Internal, "Password hash error: %v", err)
	}

	ctxDB2, cancel2 := context.WithTimeout(ctx, 2*time.Second)
	defer cancel2()

	err = s.Repo.CreateUser(ctxDB2, req.Username, string(hashedPassword), req.Email)
	if err != nil {
		logger.Logger.Errorw("Failed to create user",
			"username", req.Username,
			"error", err,
			"operation", "register",
		)
		return nil, status.Errorf(codes.Internal, "Insert error: %v", err)
	}

	return &genproto.RegisterResponse{Message: "User registered successfully"}, nil
}

func (s *AuthService) Login(ctx context.Context, req *genproto.LoginRequest) (*genproto.LoginResponse, error) {
	ctxDB, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	userID, hashedPassword, err := s.Repo.GetUserForLogin(ctxDB, req.Username)
	if err != nil {
		logger.Logger.Errorw("DB error during login",
			"username", req.Username,
			"error", err,
			"operation", "login",
		)
		return nil, status.Errorf(codes.Unauthenticated, "Invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		logger.Logger.Infow("Invalid password",
			"username", req.Username,
			"operation", "login",
		)
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	token, err := jwt.GenerateToken(userID, req.Username)
	if err != nil {
		logger.Logger.Errorw("JWT error during login",
			"username", req.Username,
			"error", err,
			"operation", "login",
		)
		return nil, status.Errorf(codes.Internal, "Failed to generate token: %v", err)
	}

	logger.Logger.Infow("User logged in",
		"username", req.Username,
		"operation", "login",
	)
	return &genproto.LoginResponse{Token: token}, nil
}

func (s *AuthService) ValidateToken(ctx context.Context, req *genproto.ValidateTokenRequest) (*genproto.ValidateTokenResponse, error) {
	claims, err := jwt.ValidateToken(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "Invalid token")
	}
	return &genproto.ValidateTokenResponse{Valid: true, Username: claims.Username}, nil
}
