package main

import (
	"JwtSecurityImplementation/controllers"
	"JwtSecurityImplementation/internal/config"
	"JwtSecurityImplementation/middleware"
	"JwtSecurityImplementation/repositories"
	"JwtSecurityImplementation/routes"
	"JwtSecurityImplementation/services"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Set Gin to release mode in production
	gin.SetMode(gin.ReleaseMode)

	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: No .env file found. Using default or system environment variables.")
	}

	// Initialize database
	db, err := config.InitDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Initialize repositories
	userRepo := repositories.NewUserRepository(db)
	tokenRepo := repositories.NewTokenRepository(db)

	// Initialize services
	authService := services.NewAuthService(userRepo)
	tokenService := services.NewTokenService(tokenRepo)

	// Initialize controllers
	authController := controllers.NewAuthController(authService, tokenService)

	// Initialize middleware
	jwtMiddleware := middleware.NewJWTMiddleware(tokenService)

	// Setup Gin router
	r := gin.New()

	// Add recovery and logging middleware
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	// Setup CORS if needed
	// r.Use(middleware.CORSMiddleware())

	// Setup routes
	routes.SetupAuthRoutes(r, authController, jwtMiddleware)

	// Start server
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting server on port %s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
