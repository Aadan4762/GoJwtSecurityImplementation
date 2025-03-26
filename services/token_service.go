package services

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"JwtSecurityImplementation/models"
	"JwtSecurityImplementation/repositories"

	"github.com/golang-jwt/jwt/v5"
)

type TokenService struct {
	tokenRepo *repositories.TokenRepository
	userRepo  *repositories.UserRepository
}

func NewTokenService(tokenRepo *repositories.TokenRepository) *TokenService {
	return &TokenService{
		tokenRepo: tokenRepo,
		userRepo:  userRepo,
	}
}

func (ts *TokenService) GenerateTokenPair(user *models.User) (*models.TokenDetails, error) {
	// Get token expiration from environment or use defaults
	accessTokenExpiry := getTokenExpiry("ACCESS_TOKEN_EXPIRY", 5)
	refreshTokenExpiry := getTokenExpiry("REFRESH_TOKEN_EXPIRY", 60)

	// Access Token
	accessTokenClaims := jwt.MapClaims{
		"user_id":    user.ID,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"email":      user.Email,
		"exp":        time.Now().Add(time.Minute * time.Duration(accessTokenExpiry)).Unix(),
		"token_type": "access",
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString([]byte(getJWTSecret()))
	if err != nil {
		return nil, err
	}

	// Refresh Token
	refreshTokenClaims := jwt.MapClaims{
		"user_id":    user.ID,
		"exp":        time.Now().Add(time.Minute * time.Duration(refreshTokenExpiry)).Unix(),
		"token_type": "refresh",
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(getJWTSecret()))
	if err != nil {
		return nil, err
	}

	return &models.TokenDetails{
		AccessToken:        accessTokenString,
		RefreshToken:       refreshTokenString,
		AccessTokenExpiry:  time.Now().Add(time.Minute * time.Duration(accessTokenExpiry)),
		RefreshTokenExpiry: time.Now().Add(time.Minute * time.Duration(refreshTokenExpiry)),
	}, nil
}

func (ts *TokenService) ValidateToken(tokenString string) (*jwt.Token, jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(getJWTSecret()), nil
	})

	if err != nil {
		return nil, nil, err
	}

	// Check if token is blacklisted
	if ts.tokenRepo.IsTokenBlacklisted(tokenString) {
		return nil, nil, fmt.Errorf("token is blacklisted")
	}

	if !token.Valid {
		return nil, nil, fmt.Errorf("invalid token")
	}

	return token, claims, nil
}

func (ts *TokenService) ValidateRefreshToken(refreshToken string) (*models.User, error) {
	// Validate token
	_, claims, err := ts.ValidateToken(refreshToken)
	if err != nil {
		return nil, err
	}

	// Ensure it's a refresh token
	tokenType, ok := claims["token_type"].(string)
	if !ok || tokenType != "refresh" {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Extract user ID
	userID, ok := claims["user_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid user ID in token")
	}

	// Fetch user from the database
	user, err := ts.userRepo.GetUserByID(uint(userID))
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	return user, nil
}

func (ts *TokenService) BlacklistToken(token string, expiresAt time.Time) error {
	return ts.tokenRepo.BlacklistToken(token, expiresAt)
}

func (ts *TokenService) RefreshAccessToken(refreshToken string) (string, error) {
	// Validate refresh token and get user
	user, err := ts.ValidateRefreshToken(refreshToken)
	if err != nil {
		return "", err
	}

	// Generate new access token
	accessTokenExpiry := getTokenExpiry("ACCESS_TOKEN_EXPIRY", 5)
	accessTokenClaims := jwt.MapClaims{
		"user_id":    user.ID,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"email":      user.Email,
		"exp":        time.Now().Add(time.Minute * time.Duration(accessTokenExpiry)).Unix(),
		"token_type": "access",
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessTokenString, err := accessToken.SignedString([]byte(getJWTSecret()))
	if err != nil {
		return "", err
	}

	return accessTokenString, nil
}

// Helper functions
func getTokenExpiry(envKey string, defaultMinutes int) int {
	expiryStr := os.Getenv(envKey)
	expiry, err := strconv.Atoi(expiryStr)
	if err != nil {
		return defaultMinutes
	}
	return expiry
}

func getJWTSecret() string {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Fallback to a default secret (not recommended in production)
		return "default_secret_key_please_change_in_production"
	}
	return secret
}
