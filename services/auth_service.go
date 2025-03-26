package services

import (
	"JwtSecurityImplementation/models"
	"JwtSecurityImplementation/repositories"
	"JwtSecurityImplementation/utils"
	"errors"
)

type AuthService struct {
	userRepo *repositories.UserRepository
}

func NewAuthService(userRepo *repositories.UserRepository) *AuthService {
	return &AuthService{userRepo: userRepo}
}

func (s *AuthService) Register(user *models.User) (*models.User, error) {
	// Additional validation can be added here
	if user.Email == "" {
		return nil, errors.New("email is required")
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		return nil, err
	}
	user.Password = hashedPassword

	// Create user
	return s.userRepo.CreateUser(user)
}

func (s *AuthService) Login(email, password string) (*models.User, error) {
	// Find user by email
	user, err := s.userRepo.FindUserByEmail(email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Verify password
	if !utils.CheckPasswordHash(password, user.Password) {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}
