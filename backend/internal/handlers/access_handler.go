package handlers

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"github.com/paulochiaradia/esp32-secure-access/internal/services"
	"gorm.io/gorm"
)

// AccessHandler cuida apenas da camada HTTP.
type AccessHandler struct {
	Service *services.AccessService
	DB      *gorm.DB
}

func NewAccessHandler(service *services.AccessService, db *gorm.DB) *AccessHandler {
	return &AccessHandler{Service: service, DB: db}
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
			attemptCount, isNew, pendingErr := h.upsertPendingRegistration(req.UID)
			if pendingErr != nil {
				log.Printf("Erro ao registrar pendência para UID %s: %v", req.UID, pendingErr)
			} else if isNew {
				log.Printf("Nova tag detectada e enviada para pendências: %s", req.UID)
			} else {
				log.Printf("Tag pendente %s tentou acesso novamente (%d vezes)", req.UID, attemptCount)
			}

			if auditErr := h.DB.Create(&models.AccessLog{UID: req.UID, Status: "denied", Message: "UID em aguardo de cadastro"}).Error; auditErr != nil {
				log.Printf("Erro ao gravar log de auditoria para UID %s: %v", req.UID, auditErr)
			}

			c.JSON(http.StatusForbidden, gin.H{"status": "denied", "message": "Acesso não autorizado. Tag registrada para análise."})
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

func (h *AccessHandler) upsertPendingRegistration(uid string) (attemptCount int, isNew bool, err error) {
	var pending models.PendingRegistration
	err = h.DB.Unscoped().Where("uid = ?", uid).First(&pending).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = h.DB.Create(&models.PendingRegistration{
				UID:      uid,
				LastSeen: time.Now(),
			}).Error
			return 1, true, err
		}
		return 0, false, err
	}

	if pending.DeletedAt.Valid {
		err = h.DB.Unscoped().Model(&pending).Updates(map[string]interface{}{
			"deleted_at":    nil,
			"attempt_count": 1,
			"last_seen":     time.Now(),
		}).Error
		return 1, true, err
	}

	attemptCount = pending.AttemptCount + 1
	err = h.DB.Model(&pending).Updates(map[string]interface{}{
		"attempt_count": pending.AttemptCount + 1,
		"last_seen":     time.Now(),
	}).Error

	return attemptCount, false, err
}

// GET /v1/users/pending
func (h *AccessHandler) ListPending(c *gin.Context) {
	var pending []models.PendingRegistration
	if err := h.DB.Order("last_seen desc").Find(&pending).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Falha ao listar pendências"})
		return
	}

	c.JSON(http.StatusOK, pending)
}

// POST /v1/users/register
func (h *AccessHandler) RegisterFromPending(c *gin.Context) {
	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Dados inválidos"})
		return
	}

	// Transação para garantir consistência entre criação do usuário e remoção da pendência.
	err := h.DB.Transaction(func(tx *gorm.DB) error {
		newUser := models.User{UID: req.UID, Name: req.Name, Active: true}
		if err := tx.Create(&newUser).Error; err != nil {
			return err
		}

		return tx.Unscoped().Where("uid = ?", req.UID).Delete(&models.PendingRegistration{}).Error
	})

	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Erro ao processar cadastro: " + err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Usuário " + req.Name + " ativado com sucesso!"})
}
