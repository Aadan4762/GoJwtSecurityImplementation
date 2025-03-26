package routes

import (
	"JwtSecurityImplementation/controllers"
	"JwtSecurityImplementation/middleware"

	"github.com/gin-gonic/gin"
)

func SetupAuthRoutes(r *gin.Engine, authController *controllers.AuthController, jwtMiddleware *middleware.JWTMiddleware) {
	// Public routes
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/register", authController.Register)
		authGroup.POST("/login", authController.Login)
		authGroup.POST("/refresh", authController.RefreshToken)
	}

	// Protected routes
	protectedGroup := r.Group("/auth")
	protectedGroup.Use(jwtMiddleware.Authenticate())
	{
		protectedGroup.POST("/logout", authController.Logout)
		// Add more protected routes as needed
	}

	// Optional: Health check route
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "healthy",
		})
	})
}
