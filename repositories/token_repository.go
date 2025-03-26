package repositories

import (
	"time"

	"gorm.io/gorm"
)

// BlacklistedToken represents a blacklisted JWT token in the database
type BlacklistedToken struct {
	gorm.Model
	Token     string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"not null"`
}

type TokenRepository struct {
	db *gorm.DB
}

// NewTokenRepository creates a new instance of TokenRepository
func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// BlacklistToken adds a token to the blacklist
func (r *TokenRepository) BlacklistToken(token string, expiresAt time.Time) error {
	// Remove any expired blacklisted tokens first
	r.removeExpiredTokens()

	// Create new blacklisted token entry
	blacklistedToken := BlacklistedToken{
		Token:     token,
		ExpiresAt: expiresAt,
	}

	return r.db.Create(&blacklistedToken).Error
}

// IsTokenBlacklisted checks if a token has been blacklisted
func (r *TokenRepository) IsTokenBlacklisted(token string) bool {
	var count int64
	result := r.db.Model(&BlacklistedToken{}).
		Where("token = ? AND expires_at > ?", token, time.Now()).
		Count(&count)

	return result.Error == nil && count > 0
}

// removeExpiredTokens cleans up expired blacklisted tokens
func (r *TokenRepository) removeExpiredTokens() {
	r.db.Where("expires_at < ?", time.Now()).Delete(&BlacklistedToken{})
}

// CleanupBlacklistedTokens provides a method to manually trigger token cleanup
func (r *TokenRepository) CleanupBlacklistedTokens() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&BlacklistedToken{}).Error
}
