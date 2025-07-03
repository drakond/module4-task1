package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/drakond/module4-task1/module4-task1/pkg/api"
)

type server struct {
	pb.UnimplementedAuthServiceServer
	db *sql.DB
}

func (s *server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username=$1)", req.Username).Scan(&exists)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "DB error: %v", err)
	}
	if exists {
		return nil, status.Errorf(codes.AlreadyExists, "user already exists")
	}

	_, err = s.db.Exec(`
        INSERT INTO users (username, password_hash, email) 
        VALUES ($1, $2, $3)`,
		req.Username, req.Password, req.Username+"@example.com",
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Insert error: %v", err)
	}

	return &pb.RegisterResponse{Message: "User registered successfully"}, nil
}

func (s *server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	var password string
	err := s.db.QueryRow("SELECT password_hash FROM users WHERE username=$1", req.Username).Scan(&password)
	if err == sql.ErrNoRows {
		return nil, status.Errorf(codes.NotFound, "user not found")
	} else if err != nil {
		return nil, status.Errorf(codes.Internal, "DB error: %v", err)
	}

	if password != req.Password {
		return nil, status.Errorf(codes.Unauthenticated, "invalid password")
	}

	return &pb.LoginResponse{Token: "token123"}, nil
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
	pb.RegisterAuthServiceServer(grpcServer, &server{db: db})

	fmt.Printf("gRPC server started on :%s\n", grpcPort)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
