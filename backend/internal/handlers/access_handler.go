package handlers

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/apiresponse"
	"github.com/paulochiaradia/esp32-secure-access/internal/middleware"
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
		apiresponse.WriteError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Payload inválido")
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
			apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Erro interno")
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
		apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Falha ao listar pendências")
		return
	}

	c.JSON(http.StatusOK, pending)
}

// POST /v1/users/register
func (h *AccessHandler) RegisterFromPending(c *gin.Context) {
	adminUserID := adminUserIDFromContext(c)
	ip := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	var req models.CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = h.DB.Create(&models.AdminAuditLog{
			AdminUserID:  adminUserID,
			Action:       "admin.users.register",
			TargetType:   "pending_registration",
			Status:       "failed",
			IP:           ip,
			UserAgent:    userAgent,
			MetadataJSON: `{"reason":"invalid_payload"}`,
		}).Error
		apiresponse.WriteError(c, http.StatusBadRequest, "VALIDATION_ERROR", "Dados inválidos")
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
		_ = h.DB.Create(&models.AdminAuditLog{
			AdminUserID:  adminUserID,
			Action:       "admin.users.register",
			TargetType:   "pending_registration",
			TargetID:     req.UID,
			Status:       "failed",
			IP:           ip,
			UserAgent:    userAgent,
			MetadataJSON: `{"reason":"operation_failed"}`,
		}).Error
		apiresponse.WriteError(c, http.StatusConflict, "CONFLICT", "Erro ao processar cadastro: "+err.Error())
		return
	}

	_ = h.DB.Create(&models.AdminAuditLog{
		AdminUserID: adminUserID,
		Action:      "admin.users.register",
		TargetType:  "user",
		TargetID:    req.UID,
		Status:      "success",
		IP:          ip,
		UserAgent:   userAgent,
	}).Error

	c.JSON(http.StatusCreated, gin.H{"message": "Usuário " + req.Name + " ativado com sucesso!"})
}

func (h *AccessHandler) ListAuditLogs(c *gin.Context) {
	page := parseIntQuery(c, "page", 1)
	limit := parseIntQuery(c, "limit", 20)
	if limit > 100 {
		limit = 100
	}
	if page < 1 {
		page = 1
	}

	action := c.Query("action")
	status := c.Query("status")
	from := c.Query("from")
	to := c.Query("to")

	query := h.DB.Model(&models.AdminAuditLog{})
	if action != "" {
		query = query.Where("action = ?", action)
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if from != "" {
		query = query.Where("created_at >= ?", from)
	}
	if to != "" {
		query = query.Where("created_at <= ?", to)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Falha ao listar auditoria")
		return
	}

	var logs []models.AdminAuditLog
	offset := (page - 1) * limit
	if err := query.Order("created_at desc").Limit(limit).Offset(offset).Find(&logs).Error; err != nil {
		apiresponse.WriteError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "Falha ao listar auditoria")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"data":   logs,
		"pagination": gin.H{
			"page":  page,
			"limit": limit,
			"total": total,
		},
	})
}

func parseIntQuery(c *gin.Context, key string, defaultValue int) int {
	value := c.Query(key)
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return parsed
}

func adminUserIDFromContext(c *gin.Context) *uint {
	v, exists := c.Get(middleware.AdminUserIDContextKey)
	if !exists {
		return nil
	}

	id, ok := v.(uint)
	if !ok {
		return nil
	}

	return &id
}
