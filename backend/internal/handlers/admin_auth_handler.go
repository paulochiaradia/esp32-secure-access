package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/apiresponse"
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
		apiresponse.WriteError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Payload inválido")
		return
	}

	bootstrapToken := c.GetHeader("X-Bootstrap-Token")
	result, err := h.Service.BootstrapFirstAdmin(req.Username, req.Password, req.Role, bootstrapToken, h.BootstrapToken, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrBootstrapDisabled):
			apiresponse.WriteError(c, http.StatusForbidden, "AUTH_FORBIDDEN", "Bootstrap desabilitado")
		case errors.Is(err, services.ErrAdminAlreadyExists):
			apiresponse.WriteError(c, http.StatusConflict, "CONFLICT", "Administrador já existente")
		default:
			apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Erro interno")
		}
		return
	}

	c.JSON(http.StatusCreated, gin.H{"status": "ok", "user": result})
}

func (h *AdminAuthHandler) Login(c *gin.Context) {
	var req models.AdminLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresponse.WriteError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Payload inválido")
		return
	}

	result, err := h.Service.Login(req.Username, req.Password, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidAdminCredentials):
			apiresponse.WriteError(c, http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "Credenciais inválidas")
		case errors.Is(err, services.ErrAdminInactive):
			apiresponse.WriteError(c, http.StatusForbidden, "AUTH_FORBIDDEN", "Usuário admin inativo")
		default:
			apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Erro interno")
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

func (h *AdminAuthHandler) Refresh(c *gin.Context) {
	var req models.AdminRefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresponse.WriteError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Payload inválido")
		return
	}

	result, err := h.Service.Refresh(req.RefreshToken, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidRefreshToken):
			apiresponse.WriteError(c, http.StatusUnauthorized, "AUTH_TOKEN_INVALID", "Refresh token inválido")
		case errors.Is(err, services.ErrRefreshSessionRevoked):
			apiresponse.WriteError(c, http.StatusUnauthorized, "AUTH_REFRESH_REVOKED", "Refresh token revogado")
		case errors.Is(err, services.ErrRefreshSessionExpired):
			apiresponse.WriteError(c, http.StatusUnauthorized, "AUTH_TOKEN_EXPIRED", "Refresh token expirado")
		default:
			apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Erro interno")
		}
		return
	}

	c.JSON(http.StatusOK, result)
}

func (h *AdminAuthHandler) Logout(c *gin.Context) {
	adminUserID, ok := adminUserIDFromAuthContext(c)
	if !ok {
		apiresponse.WriteError(c, http.StatusUnauthorized, "AUTH_TOKEN_INVALID", "Token de acesso inválido")
		return
	}

	var req models.AdminLogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresponse.WriteError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Payload inválido")
		return
	}

	err := h.Service.Logout(adminUserID, req.RefreshToken, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidRefreshToken), errors.Is(err, services.ErrRefreshSessionRevoked):
			apiresponse.WriteError(c, http.StatusUnauthorized, "AUTH_TOKEN_INVALID", "Refresh token inválido")
		default:
			apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Erro interno")
		}
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *AdminAuthHandler) ChangePassword(c *gin.Context) {
	adminUserID, ok := adminUserIDFromAuthContext(c)
	if !ok {
		apiresponse.WriteError(c, http.StatusUnauthorized, "AUTH_TOKEN_INVALID", "Token de acesso inválido")
		return
	}

	var req models.AdminChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresponse.WriteError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Payload inválido")
		return
	}

	revokedCount, err := h.Service.ChangePassword(adminUserID, req.CurrentPassword, req.NewPassword, c.ClientIP(), c.GetHeader("User-Agent"))
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidCurrentPassword):
			apiresponse.WriteError(c, http.StatusUnauthorized, "AUTH_INVALID_CREDENTIALS", "Senha atual inválida")
		case errors.Is(err, services.ErrAdminUserNotFound):
			apiresponse.WriteError(c, http.StatusNotFound, "NOT_FOUND", "Administrador não encontrado")
		default:
			apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Erro interno")
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "revoked_sessions": revokedCount})
}

func (h *AdminAuthHandler) RevokeAllSessions(c *gin.Context) {
	requesterID, ok := adminUserIDFromAuthContext(c)
	if !ok {
		apiresponse.WriteError(c, http.StatusUnauthorized, "AUTH_TOKEN_INVALID", "Token de acesso inválido")
		return
	}

	var req models.AdminRevokeSessionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresponse.WriteError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Payload inválido")
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
			apiresponse.WriteError(c, http.StatusNotFound, "NOT_FOUND", "Administrador não encontrado")
		default:
			apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Erro interno")
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
