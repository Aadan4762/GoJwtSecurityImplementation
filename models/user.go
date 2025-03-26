package models

import (
	"gorm.io/gorm"
	"time"
)

type User struct {
	gorm.Model
	FirstName       string `gorm:"type:varchar(100);not null" json:"firstName" validate:"required"`
	LastName        string `gorm:"type:varchar(100);not null" json:"lastName" validate:"required"`
	Email           string `gorm:"type:varchar(100);uniqueIndex;not null" json:"email" validate:"required,email"`
	Password        string `gorm:"type:varchar(255);not null" json:"-"`
	ConfirmPassword string `gorm:"-" json:"confirmPassword" validate:"required,eqfield=Password"`
}

type TokenDetails struct {
	AccessToken        string
	RefreshToken       string
	AccessTokenExpiry  time.Time
	RefreshTokenExpiry time.Time
}

type BlacklistedToken struct {
	Token     string `gorm:"primaryKey"`
	ExpiresAt time.Time
}
