package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	models "plaxterapi/Models"
	"plaxterapi/prisma/db"
)

var ErrUserAlreadyExists = errors.New("user already exists")

// UserRegistrationService defines the behaviour required to register a new user.
type UserRegistrationService interface {
	RegisterUser(ctx context.Context, payload models.SignUpRequest) error
}

// PrismaUserService persists users via Prisma.
type PrismaUserService struct {
	client *db.PrismaClient
}

// NewPrismaUserService wires a Prisma-backed user service. The caller is responsible
// for managing the lifecycle of the provided client.
func NewPrismaUserService(client *db.PrismaClient) *PrismaUserService {
	return &PrismaUserService{client: client}
}

// RegisterUser hashes the supplied password, checks for duplicates, and stores the user.
func (s *PrismaUserService) RegisterUser(ctx context.Context, payload models.SignUpRequest) error {
	if s.client == nil {
		return errors.New("prisma client not configured")
	}

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Fail fast when a user with the same username already exists.
	_, err := s.client.User.FindUnique(
		db.User.Username.Equals(payload.Username),
	).Exec(ctx)
	switch {
	case err == nil:
		return ErrUserAlreadyExists
	case errors.Is(err, db.ErrNotFound):

	default:
		return fmt.Errorf("lookup existing user: %w", err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password.Reveal()), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	params := []db.UserSetParam{
		db.User.Username.Set(payload.Username),
		db.User.Password.Set(string(hashedPassword)),
	}

	if payload.Email != "" {
		params = append(params, db.User.Email.Set(payload.Email))
	}
	if payload.FirstName != "" {
		params = append(params, db.User.FirstName.Set(payload.FirstName))
	}
	if payload.LastName != "" {
		params = append(params, db.User.LastName.Set(payload.LastName))
	}

	if _, err := s.client.User.CreateOne(params...).Exec(ctx); err != nil {
		return fmt.Errorf("create user: %w", err)
	}

	return nil
}
