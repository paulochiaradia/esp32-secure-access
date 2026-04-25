package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/middleware"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"github.com/paulochiaradia/esp32-secure-access/internal/services"
)

type AdminAuthHandler struct {
	Service        *services.AdminAuthService
	BootstrapToken string
}

func NewAdminAuthHandler(service *services.AdminAuthService, bootstrapToken string) *AdminAuthHandler {
	return &AdminAuthHandler{Service: service, BootstrapToken: bootstrapToken}
}

func (h *AdminAuthHandler) Bootstrap(c *gin.Context) {
	var req models.AdminBootstrapRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Payload inválido"})
		return
	}

	bootstrapToken := c.GetHeader("X-Bootstrap-Token")
	result, err := h.Service.BootstrapFirstAdmin(req.Username, req.Password, req.Role, bootstrapToken, h.BootstrapToken, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrBootstrapDisabled):
			c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Bootstrap desabilitado"})
		case errors.Is(err, services.ErrAdminAlreadyExists):
			c.JSON(http.StatusConflict, gin.H{"status": "error", "message": "Administrador já existente"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Erro interno"})
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{"status": "ok", "user": result})
}

func (h *AdminAuthHandler) Login(c *gin.Context) {
	var req models.AdminLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Payload inválido"})
		return
	}

	result, err := h.Service.Login(req.Username, req.Password, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidAdminCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Credenciais inválidas"})
		case errors.Is(err, services.ErrAdminInactive):
			c.JSON(http.StatusForbidden, gin.H{"status": "error", "message": "Usuário admin inativo"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Erro interno"})
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

func (h *AdminAuthHandler) Refresh(c *gin.Context) {
	var req models.AdminRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Payload inválido"})
		return
	}

	result, err := h.Service.Refresh(req.RefreshToken, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidRefreshToken):
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Refresh token inválido"})
		case errors.Is(err, services.ErrRefreshSessionRevoked):
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Refresh token revogado"})
		case errors.Is(err, services.ErrRefreshSessionExpired):
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Refresh token expirado"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Erro interno"})
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

func (h *AdminAuthHandler) Logout(c *gin.Context) {
	adminUserID, ok := adminUserIDFromAuthContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Token de acesso inválido"})
		return
	}

	var req models.AdminLogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Payload inválido"})
		return
	}

	err := h.Service.Logout(adminUserID, req.RefreshToken, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidRefreshToken), errors.Is(err, services.ErrRefreshSessionRevoked):
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Refresh token inválido"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Erro interno"})
		}
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *AdminAuthHandler) ChangePassword(c *gin.Context) {
	adminUserID, ok := adminUserIDFromAuthContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Token de acesso inválido"})
		return
	}

	var req models.AdminChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Payload inválido"})
		return
	}

	revokedCount, err := h.Service.ChangePassword(adminUserID, req.CurrentPassword, req.NewPassword, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidCurrentPassword):
			c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Senha atual inválida"})
		case errors.Is(err, services.ErrAdminUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Administrador não encontrado"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Erro interno"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "revoked_sessions": revokedCount})
}

func (h *AdminAuthHandler) RevokeAllSessions(c *gin.Context) {
	requesterID, ok := adminUserIDFromAuthContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Token de acesso inválido"})
		return
	}

	var req models.AdminRevokeSessionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "error", "message": "Payload inválido"})
		return
	}

	targetID := requesterID
	if req.UserID != nil {
		targetID = *req.UserID
	}

	revokedCount, err := h.Service.RevokeAllSessions(requesterID, targetID, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrAdminUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"status": "error", "message": "Administrador não encontrado"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Erro interno"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "revoked_sessions": revokedCount, "target_user_id": targetID})
}

func adminUserIDFromAuthContext(c *gin.Context) (uint, bool) {
	v, exists := c.Get(middleware.AdminUserIDContextKey)
	if !exists {
		return 0, false
	}
	adminUserID, ok := v.(uint)
	if !ok {
		return 0, false
	}
	return adminUserID, true
}
