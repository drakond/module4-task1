package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"os/signal"
	"syscall"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/drakond/module4-task1/module4-task1/pkg/api"
	"github.com/drakond/module4-task1/module4-task1/pkg/jwt"
)

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	db *sql.DB
}

func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username=$1)", req.Username).Scan(&exists)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DB error: %v", err)
	}
	if exists {
		return nil, status.Errorf(codes.AlreadyExists, "user already exists")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Password hash error: %v", err)
	}

	_, err = s.db.Exec(`
        INSERT INTO users (username, password_hash, email) 
        VALUES ($1, $2, $3)`,
		req.Username, hashedPassword, req.Username+"@example.com",
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Insert error: %v", err)
	}

	return &pb.RegisterResponse{Message: "User registered successfully"}, nil
}

func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var userID string
	var hashedPassword string
	err := s.db.QueryRow("SELECT id, password_hash FROM users WHERE username=$1", req.Username).Scan(&userID, &hashedPassword)
	if err != nil {
		log.Printf("DB error: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "Invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		log.Printf("Password mismatch: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "Invalid credentials")
	}
	token, err := jwt.GenerateToken(userID, req.Username, time.Hour)
	if err != nil {
		log.Printf("JWT error: %v", err)
		return nil, status.Errorf(codes.Internal, "Failed to generate token: %v", err)
	}
	return &pb.LoginResponse{Token: token}, nil
}

func (s *AuthServiceServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	claims, err := jwt.ValidateToken(req.Token)
	if err != nil {
		return &pb.ValidateTokenResponse{Valid: false, Error: "Invalid token"}, nil
	}
	return &pb.ValidateTokenResponse{Valid: true, Username: claims.Username}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func buildDSN() string {
	host := getEnv("DB_HOST", "localhost")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "user")
	password := getEnv("DB_PASSWORD", "password")
	dbname := getEnv("DB_NAME", "module4-task1")
	sslmode := getEnv("DB_SSLMODE", "disable")

	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode)
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, using system environment variables")
	}

	if err := jwt.Init(); err != nil {
		log.Fatalf("failed to initialize JWT: %v", err)
	}

	dsn := buildDSN()

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("failed to connect to DB: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("failed to ping DB: %v", err)
	}

	grpcPort := getEnv("GRPC_PORT", "50051")
	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAuthServiceServer(grpcServer, &AuthServiceServer{db: db})

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		log.Println("Shutting down gRPC server...")
		grpcServer.GracefulStop()
	}()

	fmt.Printf("gRPC server started on :%s\n", grpcPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
