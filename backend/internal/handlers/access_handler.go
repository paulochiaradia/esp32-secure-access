package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
)

func HandleAccessRequest(c *gin.Context) {
	var req models.AccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid payload"})
		return
	}

	c.JSON(http.StatusOK, models.AccessResponse{
		Status:  "authorized",
		Message: "Welcome to the secure facility",
		User:    "Paulo Chiaradia",
	})
}
