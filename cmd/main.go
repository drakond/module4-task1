package main

import (
	"context"
	"database/sql"
	"github.com/drakond/module4-task1/grpc/genproto"
	"github.com/drakond/module4-task1/internal/config"
	"github.com/drakond/module4-task1/internal/repo"
	"github.com/drakond/module4-task1/internal/service"
	"github.com/drakond/module4-task1/pkg/jwt"
	"github.com/drakond/module4-task1/pkg/logger"
	"log"
	"net"
	"os/signal"
	"syscall"

	_ "github.com/lib/pq"
	"google.golang.org/grpc"
)

func main() {
	if err := logger.Init(); err != nil {
		log.Fatalf("failed to initialize logger: %v", err)
	}
	defer logger.Logger.Sync()

	config.LoadEnv()

	if err := jwt.Init(); err != nil {
		logger.Logger.Fatalw("failed to initialize JWT", "error", err)
	}

	dsn := config.BuildDSN()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		logger.Logger.Fatalw("failed to connect to DB", "error", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Logger.Errorw("failed to close DB", "error", err)
		}
	}()

	if err := db.Ping(); err != nil {
		logger.Logger.Fatalw("failed to ping DB", "error", err)
	}

	userRepo := &repo.UserRepo{DB: db}
	authService := &service.AuthService{Repo: userRepo}

	grpcPort := config.GetEnv("GRPC_PORT", "50051")
	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		logger.Logger.Fatalw("failed to listen", "error", err)
	}

	grpcServer := grpc.NewServer()
	genproto.RegisterAuthServiceServer(grpcServer, authService)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Logger.Infow("gRPC server started", "port", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			logger.Logger.Errorw("gRPC server exited", "error", err)
		}
	}()

	<-ctx.Done()
	logger.Logger.Infow("Shutting down application...")

	grpcServer.GracefulStop()
	logger.Logger.Infow("gRPC server stopped")

	logger.Logger.Infow("Shutdown complete")
}
