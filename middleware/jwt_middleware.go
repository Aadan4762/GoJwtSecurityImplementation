package middleware

import (
	"JwtSecurityImplementation/pkg/responses"
	"JwtSecurityImplementation/services"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type JWTMiddleware struct {
	tokenService *services.TokenService
}

func NewJWTMiddleware(tokenService *services.TokenService) *JWTMiddleware {
	return &JWTMiddleware{tokenService: tokenService}
}

func (jm *JWTMiddleware) Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			responses.ErrorResponse(c, http.StatusUnauthorized, "Authorization token missing", nil)
			c.Abort()
			return
		}

		// Extract the token (remove "Bearer " prefix)
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate the token
		token, claims, err := jm.tokenService.ValidateToken(tokenString)
		if err != nil {
			responses.ErrorResponse(c, http.StatusUnauthorized, "Invalid token", err)
			c.Abort()
			return
		}

		// Set user claims in the context for further use
		c.Set("user_id", claims["user_id"])
		c.Set("email", claims["email"])
		c.Set("token", token)

		c.Next()
	}
}
