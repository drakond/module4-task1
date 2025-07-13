package service

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/drakond/module4-task1/grpc/genproto"
	"github.com/drakond/module4-task1/pkg/jwt"
	"github.com/drakond/module4-task1/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type MockUserRepo struct {
	mock.Mock
}

func (m *MockUserRepo) UserExists(ctx context.Context, username string) (bool, error) {
	args := m.Called(ctx, username)
	return args.Bool(0), args.Error(1)
}

func (m *MockUserRepo) CreateUser(ctx context.Context, username, hashedPassword, email string) error {
	args := m.Called(ctx, username, hashedPassword, email)
	return args.Error(0)
}

func (m *MockUserRepo) GetUserForLogin(ctx context.Context, username string) (userID, hashedPassword string, err error) {
	args := m.Called(ctx, username)
	return args.String(0), args.String(1), args.Error(2)
}

func TestMain(m *testing.M) {
	if err := logger.Init(); err != nil {
		panic(err)
	}
	os.Setenv("JWT_SECRET", "testsecret_123456789012345678901234567890")
	if err := jwt.Init(); err != nil {
		panic(err)
	}
	m.Run()
}

func TestAuthService_Register_Success(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	req := &genproto.RegisterRequest{
		Username: "testuser",
		Password: "testpass",
		Email:    "test@example.com",
	}

	mockRepo.On("UserExists", mock.Anything, "testuser").Return(false, nil)
	mockRepo.On("CreateUser", mock.Anything, "testuser", mock.Anything, "test@example.com").Return(nil)

	resp, err := service.Register(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "User registered successfully", resp.Message)
	mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_UserAlreadyExists(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	req := &genproto.RegisterRequest{
		Username: "existinguser",
		Password: "testpass",
		Email:    "test@example.com",
	}

	mockRepo.On("UserExists", mock.Anything, "existinguser").Return(true, nil)

	resp, err := service.Register(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.AlreadyExists, st.Code())
	assert.Contains(t, st.Message(), "user already exists")

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_DBErrorOnUserExists(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	req := &genproto.RegisterRequest{
		Username: "testuser",
		Password: "testpass",
		Email:    "test@example.com",
	}

	mockRepo.On("UserExists", mock.Anything, "testuser").Return(false, errors.New("database error"))

	resp, err := service.Register(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Contains(t, st.Message(), "DB error")

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Register_DBErrorOnCreateUser(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	req := &genproto.RegisterRequest{
		Username: "testuser",
		Password: "testpass",
		Email:    "test@example.com",
	}

	mockRepo.On("UserExists", mock.Anything, "testuser").Return(false, nil)
	mockRepo.On("CreateUser", mock.Anything, "testuser", mock.Anything, "test@example.com").Return(errors.New("insert error"))

	resp, err := service.Register(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Contains(t, st.Message(), "Insert error")

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_Success(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	password := "testpass"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	req := &genproto.LoginRequest{
		Username: "testuser",
		Password: password,
	}

	mockRepo.On("GetUserForLogin", mock.Anything, "testuser").Return("user123", string(hashedPassword), nil)

	resp, err := service.Login(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_UserNotFound(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	req := &genproto.LoginRequest{
		Username: "nonexistent",
		Password: "testpass",
	}

	mockRepo.On("GetUserForLogin", mock.Anything, "nonexistent").Return("", "", sql.ErrNoRows)

	resp, err := service.Login(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "Invalid credentials")

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_InvalidPassword(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	correctPassword := "correctpass"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)

	req := &genproto.LoginRequest{
		Username: "testuser",
		Password: "wrongpass",
	}

	mockRepo.On("GetUserForLogin", mock.Anything, "testuser").Return("user123", string(hashedPassword), nil)

	resp, err := service.Login(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "invalid credentials")

	mockRepo.AssertExpectations(t)
}

func TestAuthService_Login_DBError(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	req := &genproto.LoginRequest{
		Username: "testuser",
		Password: "testpass",
	}

	mockRepo.On("GetUserForLogin", mock.Anything, "testuser").Return("", "", errors.New("database error"))

	resp, err := service.Login(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "Invalid credentials")

	mockRepo.AssertExpectations(t)
}

func TestAuthService_ValidateToken_ValidToken(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	token, err := jwt.GenerateToken("user123", "testuser")
	assert.NoError(t, err)

	req := &genproto.ValidateTokenRequest{
		Token: token,
	}

	resp, err := service.ValidateToken(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Valid)
	assert.Equal(t, "testuser", resp.Username)
}

func TestAuthService_ValidateToken_InvalidToken(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	req := &genproto.ValidateTokenRequest{
		Token: "invalid.token.here",
	}

	resp, err := service.ValidateToken(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "Invalid token")
}

func TestAuthService_ValidateToken_EmptyToken(t *testing.T) {
	mockRepo := new(MockUserRepo)
	service := &AuthService{Repo: mockRepo}

	req := &genproto.ValidateTokenRequest{
		Token: "",
	}

	resp, err := service.ValidateToken(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)

	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "Invalid token")
}
