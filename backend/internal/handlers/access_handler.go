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
		c.JSON(http.StatusBadRequest, models.ErrorResponse{Status: "error", Message: "Payload inválido"})
		return
	}

	result, err := h.Service.ProcessAccessRequest(req)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidTimestamp):
			c.JSON(http.StatusUnauthorized, models.AccessResponse{Status: "denied", Message: "Requisição fora da janela de tempo"})
		case errors.Is(err, services.ErrInvalidSignature):
			log.Printf("TENTATIVA DE INVASÃO: UID %s enviou assinatura inválida", req.UID)
			c.JSON(http.StatusUnauthorized, models.AccessResponse{Status: "denied", Message: "Falha na segurança"})
		case errors.Is(err, services.ErrReplayDetected):
			c.JSON(http.StatusUnauthorized, models.AccessResponse{Status: "denied", Message: "Replay detectado"})
		case errors.Is(err, services.ErrUserNotFound):
			c.JSON(http.StatusForbidden, models.AccessResponse{Status: "denied", Message: "Acesso não autorizado"})
		default:
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{Status: "error", Message: "Erro interno"})
		}
		return
	}

	c.JSON(http.StatusOK, models.AccessResponse{
		Status:  "authorized",
		Message: "Bem-vindo, " + result.UserName,
		User:    result.UserName,
	})
}
