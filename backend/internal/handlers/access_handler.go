package handlers

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"github.com/paulochiaradia/esp32-secure-access/internal/services"
)

// AccessHandler cuida apenas da camada HTTP.
type AccessHandler struct {
	Service *services.AccessService
}

func NewAccessHandler(service *services.AccessService) *AccessHandler {
	return &AccessHandler{Service: service}
}

func (h *AccessHandler) HandleAccessRequest(c *gin.Context) {
	var req models.AccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("Erro de parse: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Payload inválido"})
		return
	}

	result, err := h.Service.ProcessAccessRequest(req)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidSignature):
			log.Printf("TENTATIVA DE INVASÃO: UID %s enviou assinatura inválida", req.UID)
			c.JSON(http.StatusUnauthorized, gin.H{"status": "denied", "message": "Falha na segurança"})
		case errors.Is(err, services.ErrUserNotFound):
			c.JSON(http.StatusForbidden, gin.H{"status": "denied", "message": "Acesso não autorizado"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"status": "error", "message": "Erro interno"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "authorized",
		"message": "Bem-vindo, " + result.UserName,
		"user":    result.UserName,
	})
}
