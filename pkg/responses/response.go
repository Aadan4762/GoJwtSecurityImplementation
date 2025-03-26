package responses

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// StandardResponse represents the structure of standard API responses
type StandardResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

// SuccessResponse sends a successful HTTP response
func SuccessResponse(c *gin.Context, statusCode int, message string, data interface{}) {
	response := StandardResponse{
		Success: true,
		Message: message,
		Data:    data,
	}

	c.JSON(statusCode, response)
}

// ErrorResponse sends an error HTTP response
func ErrorResponse(c *gin.Context, statusCode int, message string, err error) {
	var errorDetails interface{}
	if err != nil {
		errorDetails = err.Error()
	}

	response := StandardResponse{
		Success: false,
		Message: message,
		Error:   errorDetails,
	}

	c.JSON(statusCode, response)
}

// ValidationErrorResponse sends a detailed validation error response
func ValidationErrorResponse(c *gin.Context, errors interface{}) {
	response := StandardResponse{
		Success: false,
		Message: "Validation failed",
		Error:   errors,
	}

	c.JSON(http.StatusBadRequest, response)
}

// UnauthorizedResponse sends an unauthorized response
func UnauthorizedResponse(c *gin.Context, message string) {
	ErrorResponse(c, http.StatusUnauthorized, message, nil)
}

// BadRequestResponse sends a bad request response
func BadRequestResponse(c *gin.Context, message string, err error) {
	ErrorResponse(c, http.StatusBadRequest, message, err)
}

// InternalServerErrorResponse sends an internal server error response
func InternalServerErrorResponse(c *gin.Context, err error) {
	ErrorResponse(c, http.StatusInternalServerError, "Internal server error", err)
}
