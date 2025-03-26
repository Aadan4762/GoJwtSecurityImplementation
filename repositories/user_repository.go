package repositories

import (
	"JwtSecurityImplementation/models"
	"errors"

	"gorm.io/gorm"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(user *models.User) (*models.User, error) {
	// Check if email already exists
	var existingUser models.User
	result := r.db.Where("email = ?", user.Email).First(&existingUser)
	if result.Error == nil {
		return nil, errors.New("email already exists")
	}

	// Create new user
	if err := r.db.Create(user).Error; err != nil {
		return nil, err
	}

	// Clear sensitive data before returning
	user.Password = ""
	user.ConfirmPassword = ""
	return user, nil
}

func (r *UserRepository) FindUserByEmail(email string) (*models.User, error) {
	var user models.User
	result := r.db.Where("email = ?", email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, result.Error
	}
	return &user, nil
}

func (r *UserRepository) GetUserByID(userID uint) (*models.User, error) {
	var user models.User
	result := r.db.First(&user, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, errors.New("user not found")
		}
		return nil, result.Error
	}
	return &user, nil
}
