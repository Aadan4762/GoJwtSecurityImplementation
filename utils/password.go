package utils

import (
	"os"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	// Get bcrypt cost from environment or use default
	cost := getBcryptCost()

	bytes, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Helper function to get bcrypt cost from environment
func getBcryptCost() int {
	costStr := os.Getenv("BCRYPT_COST")
	cost, err := strconv.Atoi(costStr)
	if err != nil || cost < 10 || cost > 16 {
		// Default to 14 if not set or invalid
		return 14
	}
	return cost
}
