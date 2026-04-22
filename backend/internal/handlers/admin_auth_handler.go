package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"github.com/paulochiaradia/esp32-secure-access/internal/services"
)

type AdminAuthHandler struct {
	Service *services.AdminAuthService
}

func NewAdminAuthHandler(service *services.AdminAuthService) *AdminAuthHandler {
	return &AdminAuthHandler{Service: service}
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
