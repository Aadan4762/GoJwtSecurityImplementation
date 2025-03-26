package controllers

import (
	"JwtSecurityImplementation/models"
	"JwtSecurityImplementation/pkg/responses"
	"JwtSecurityImplementation/services"
	"JwtSecurityImplementation/utils"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type AuthController struct {
	authService  *services.AuthService
	tokenService *services.TokenService
}

func NewAuthController(authService *services.AuthService, tokenService *services.TokenService) *AuthController {
	return &AuthController{
		authService:  authService,
		tokenService: tokenService,
	}
}

func (ac *AuthController) Register(c *gin.Context) {
	var user models.User
	if err := c.ShouldBindJSON(&user); err != nil {
		responses.ErrorResponse(c, http.StatusBadRequest, "Invalid input", err)
		return
	}

	// Validate input
	if err := utils.Validate(&user); err != nil {
		responses.ErrorResponse(c, http.StatusBadRequest, "Validation failed", err)
		return
	}

	// Validate password confirmation
	if user.Password != user.ConfirmPassword {
		responses.ErrorResponse(c, http.StatusBadRequest, "Passwords do not match", nil)
		return
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		responses.ErrorResponse(c, http.StatusInternalServerError, "Failed to hash password", err)
		return
	}
	user.Password = hashedPassword
	user.ConfirmPassword = "" // Clear confirm password after validation

	// Create user
	createdUser, err := ac.authService.Register(&user)
	if err != nil {
		responses.ErrorResponse(c, http.StatusConflict, "Registration failed", err)
		return
	}

	responses.SuccessResponse(c, http.StatusCreated, "User registered successfully", createdUser)
}

func (ac *AuthController) Login(c *gin.Context) {
	var loginRequest struct {
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}

	if err := c.ShouldBindJSON(&loginRequest); err != nil {
		responses.ErrorResponse(c, http.StatusBadRequest, "Invalid input", err)
		return
	}

	// Authenticate user
	user, err := ac.authService.Login(loginRequest.Email, loginRequest.Password)
	if err != nil {
		responses.ErrorResponse(c, http.StatusUnauthorized, "Authentication failed", err)
		return
	}

	// Generate tokens
	tokens, err := ac.tokenService.GenerateTokenPair(user)
	if err != nil {
		responses.ErrorResponse(c, http.StatusInternalServerError, "Token generation failed", err)
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "Login successful", gin.H{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

func (ac *AuthController) Logout(c *gin.Context) {
	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		responses.ErrorResponse(c, http.StatusBadRequest, "Authorization header is missing", nil)
		return
	}

	// Remove "Bearer " prefix
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")
	refreshToken := c.GetHeader("Refresh-Token")

	// Blacklist both tokens
	err := ac.tokenService.BlacklistToken(accessToken, time.Now().Add(time.Minute*5))
	if err != nil {
		responses.ErrorResponse(c, http.StatusInternalServerError, "Failed to blacklist access token", err)
		return
	}

	err = ac.tokenService.BlacklistToken(refreshToken, time.Now().Add(time.Hour*1))
	if err != nil {
		responses.ErrorResponse(c, http.StatusInternalServerError, "Failed to blacklist refresh token", err)
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "Logout successful", nil)
}

func (ac *AuthController) RefreshToken(c *gin.Context) {
	var refreshRequest struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := c.ShouldBindJSON(&refreshRequest); err != nil {
		responses.ErrorResponse(c, http.StatusBadRequest, "Invalid input", err)
		return
	}

	// Validate refresh token
	_, err := ac.tokenService.ValidateRefreshToken(refreshRequest.RefreshToken)
	if err != nil {
		responses.ErrorResponse(c, http.StatusUnauthorized, "Invalid refresh token", err)
		return
	}

	// Generate new access token
	newAccessToken, err := ac.tokenService.RefreshAccessToken(refreshRequest.RefreshToken)
	if err != nil {
		responses.ErrorResponse(c, http.StatusUnauthorized, "Token refresh failed", err)
		return
	}

	responses.SuccessResponse(c, http.StatusOK, "Token refreshed successfully", gin.H{
		"access_token": newAccessToken,
	})
}
