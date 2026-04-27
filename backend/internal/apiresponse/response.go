package apiresponse

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
)

func WriteError(c *gin.Context, status int, code, message string) {
	c.JSON(status, models.ErrorResponse{
		Status:  "error",
		Code:    code,
		Message: message,
		TraceID: TraceID(),
	})
}

func TraceID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "trace-unavailable"
	}
	return hex.EncodeToString(buf)
}
