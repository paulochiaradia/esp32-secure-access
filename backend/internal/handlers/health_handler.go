package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/gorm"
)

type HealthHandler struct {
	DB *gorm.DB
}

func NewHealthHandler(db *gorm.DB) *HealthHandler {
	return &HealthHandler{DB: db}
}

func (h *HealthHandler) HandleHealthCheck(c *gin.Context) {
	sqlDB, err := h.DB.DB()
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, models.HealthResponse{Status: "degraded", Database: "down"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		c.JSON(http.StatusServiceUnavailable, models.HealthResponse{Status: "degraded", Database: "down"})
		return
	}

	c.JSON(http.StatusOK, models.HealthResponse{Status: "ok", Database: "up"})
}
