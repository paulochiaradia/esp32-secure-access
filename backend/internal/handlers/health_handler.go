package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/apiresponse"
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

func (h *HealthHandler) HandleSecurityHealthCheck(c *gin.Context) {
	sqlDB, err := h.DB.DB()
	if err != nil {
		apiresponse.WriteError(c, http.StatusServiceUnavailable, "INTERNAL_ERROR", "Serviço degradado")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		apiresponse.WriteError(c, http.StatusServiceUnavailable, "INTERNAL_ERROR", "Serviço degradado")
		return
	}

	var activeSessions int64
	if err := h.DB.Model(&models.AdminRefreshSession{}).Where("revoked_at IS NULL AND expires_at > ?", time.Now()).Count(&activeSessions).Error; err != nil {
		apiresponse.WriteError(c, http.StatusServiceUnavailable, "INTERNAL_ERROR", "Serviço degradado")
		return
	}

	var recentFailedAuth int64
	recentWindow := time.Now().Add(-24 * time.Hour)
	if err := h.DB.Model(&models.AdminAuditLog{}).Where("action IN ? AND status = ? AND created_at >= ?", []string{"admin.auth.login", "admin.auth.refresh", "admin.auth.bootstrap", "admin.auth.logout", "admin.auth.change_password", "admin.auth.revoke_all_sessions"}, "failed", recentWindow).Count(&recentFailedAuth).Error; err != nil {
		apiresponse.WriteError(c, http.StatusServiceUnavailable, "INTERNAL_ERROR", "Serviço degradado")
		return
	}

	var expiredSessions int64
	if err := h.DB.Unscoped().Model(&models.AdminRefreshSession{}).Where("expires_at < ?", time.Now()).Count(&expiredSessions).Error; err != nil {
		apiresponse.WriteError(c, http.StatusServiceUnavailable, "INTERNAL_ERROR", "Serviço degradado")
		return
	}

	c.JSON(http.StatusOK, models.SecurityHealthResponse{
		Status:                  "ok",
		Database:                "up",
		ActiveAdminSessions:     activeSessions,
		RecentFailedAdminAuth:   recentFailedAuth,
		ExpiredRefreshSessions:  expiredSessions,
		RecentFailedLoginWindow: "24h",
	})
}
