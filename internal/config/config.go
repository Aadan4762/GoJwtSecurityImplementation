package config

import (
	"fmt"
	"log"
	"os"

	"JwtSecurityImplementation/models"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Config struct {
	DB *gorm.DB
}

func InitDatabase() (*gorm.DB, error) {
	// Get database configuration from environment variables
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")

	// Construct DSN (Data Source Name)
	dsn := fmt.Sprintf("sqlserver://%s:%s@%s:%s?database=%s&trustServerCertificate=true",
		user, password, host, port, dbName)

	// Configure logger
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			LogLevel: logger.Silent, // Change to logger.Info for verbose logging
		},
	)

	// Open database connection
	db, err := gorm.Open(sqlserver.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Auto Migrate
	err = db.AutoMigrate(&models.User{}, &models.BlacklistedToken{})
	if err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return db, nil
}
