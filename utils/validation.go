package utils

import (
	"fmt"
	"regexp"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom validations
	validate.RegisterValidation("strong_password", validateStrongPassword)
}

func Validate(data interface{}) error {
	err := validate.Struct(data)
	if err != nil {
		return formatValidationErrors(err)
	}
	return nil
}

// Custom password strength validation
func validateStrongPassword(fl validator.FieldLevel) bool {
	password := fl.Field().String()

	// Check length
	if len(password) < 8 {
		return false
	}

	// Check for at least one uppercase letter
	if !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		return false
	}

	// Check for at least one lowercase letter
	if !regexp.MustCompile(`[a-z]`).MatchString(password) {
		return false
	}

	// Check for at least one digit
	if !regexp.MustCompile(`\d`).MatchString(password) {
		return false
	}

	// Check for at least one special character
	if !regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>]`).MatchString(password) {
		return false
	}

	return true
}

// Format validation errors into a more readable format
func formatValidationErrors(err error) error {
	if err == nil {
		return nil
	}

	validationErrors, ok := err.(validator.ValidationErrors)
	if !ok {
		return err
	}

	var errorMessages []string
	for _, e := range validationErrors {
		errorMessages = append(errorMessages, formatFieldError(e))
	}

	return fmt.Errorf(string(errorMessages[0]))
}

// Format individual field validation error
func formatFieldError(e validator.FieldError) string {
	switch e.Tag() {
	case "required":
		return fmt.Sprintf("%s is required", e.Field())
	case "email":
		return fmt.Sprintf("%s must be a valid email address", e.Field())
	case "strong_password":
		return "password must be at least 8 characters long and contain uppercase, lowercase, number, and special character"
	case "eqfield":
		return fmt.Sprintf("%s must match %s", e.Field(), e.Param())
	default:
		return fmt.Sprintf("%s is invalid", e.Field())
	}
}
