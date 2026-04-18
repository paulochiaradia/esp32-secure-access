package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"github.com/paulochiaradia/esp32-secure-access/internal/repositories"
	"github.com/paulochiaradia/esp32-secure-access/internal/services"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const testSecret = "test-secret"

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("erro ao abrir banco de teste: %v", err)
	}

	err = db.AutoMigrate(
		&models.User{},
		&models.AccessLog{},
		&models.UsedNonce{},
		&models.PendingRegistration{},
	)
	if err != nil {
		t.Fatalf("erro ao fazer automigrate no banco de teste: %v", err)
	}

	return db
}

func newTestHandler(t *testing.T) (*AccessHandler, *gorm.DB) {
	t.Helper()

	db := newTestDB(t)
	service := services.NewAccessService(
		testSecret,
		repositories.NewUserRepository(db),
		repositories.NewAccessLogRepository(db),
		repositories.NewNonceRepository(db),
		2*time.Minute,
		5*time.Minute,
	)

	return NewAccessHandler(service, db), db
}

func buildAccessRequest(uid, nonce string) models.AccessRequest {
	timestamp := time.Now().Unix()
	signature := sign(uid, timestamp, nonce, testSecret)

	return models.AccessRequest{
		UID:       uid,
		Timestamp: timestamp,
		Nonce:     nonce,
		Signature: signature,
	}
}

func sign(uid string, timestamp int64, nonce, secret string) string {
	message := uid + ":" + strconv.FormatInt(timestamp, 10) + ":" + nonce
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(message))
	return hex.EncodeToString(h.Sum(nil))
}

func postJSON(t *testing.T, router *gin.Engine, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("erro ao serializar payload: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestHandleAccessRequest_UnknownUIDCreatesPendingAndAuditLog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newTestHandler(t)

	router := gin.New()
	router.POST("/v1/access", handler.HandleAccessRequest)

	w := postJSON(t, router, "/v1/access", buildAccessRequest("TAG-001", "nonce-1"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusForbidden, w.Code)
	}

	var pending models.PendingRegistration
	if err := db.Where("uid = ?", "TAG-001").First(&pending).Error; err != nil {
		t.Fatalf("pendência não encontrada: %v", err)
	}
	if pending.AttemptCount != 1 {
		t.Fatalf("attempt_count inesperado: esperado 1, obtido %d", pending.AttemptCount)
	}

	var auditLog models.AccessLog
	if err := db.Where("uid = ? AND message = ?", "TAG-001", "UID em aguardo de cadastro").First(&auditLog).Error; err != nil {
		t.Fatalf("log de auditoria não encontrado: %v", err)
	}
}

func TestHandleAccessRequest_UnknownUIDIncrementsPendingAttemptCount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newTestHandler(t)

	router := gin.New()
	router.POST("/v1/access", handler.HandleAccessRequest)

	first := postJSON(t, router, "/v1/access", buildAccessRequest("TAG-002", "nonce-a"))
	if first.Code != http.StatusForbidden {
		t.Fatalf("status da primeira tentativa inesperado: esperado %d, obtido %d", http.StatusForbidden, first.Code)
	}

	second := postJSON(t, router, "/v1/access", buildAccessRequest("TAG-002", "nonce-b"))
	if second.Code != http.StatusForbidden {
		t.Fatalf("status da segunda tentativa inesperado: esperado %d, obtido %d", http.StatusForbidden, second.Code)
	}

	var pending models.PendingRegistration
	if err := db.Where("uid = ?", "TAG-002").First(&pending).Error; err != nil {
		t.Fatalf("pendência não encontrada: %v", err)
	}
	if pending.AttemptCount != 2 {
		t.Fatalf("attempt_count inesperado: esperado 2, obtido %d", pending.AttemptCount)
	}
}

func TestListPending_ReturnsLastSeenDescending(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newTestHandler(t)

	older := models.PendingRegistration{UID: "TAG-OLD", AttemptCount: 1, LastSeen: time.Now().Add(-40 * time.Minute)}
	newer := models.PendingRegistration{UID: "TAG-NEW", AttemptCount: 1, LastSeen: time.Now().Add(-5 * time.Minute)}
	if err := db.Create(&older).Error; err != nil {
		t.Fatalf("erro ao inserir registro antigo: %v", err)
	}
	if err := db.Create(&newer).Error; err != nil {
		t.Fatalf("erro ao inserir registro novo: %v", err)
	}

	router := gin.New()
	router.GET("/v1/users/pending", handler.ListPending)

	req := httptest.NewRequest(http.MethodGet, "/v1/users/pending", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusOK, w.Code)
	}

	var response []models.PendingRegistration
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("erro ao desserializar resposta: %v", err)
	}
	if len(response) < 2 {
		t.Fatalf("resposta com quantidade inesperada: esperado ao menos 2, obtido %d", len(response))
	}
	if response[0].UID != "TAG-NEW" {
		t.Fatalf("ordenação inesperada: primeiro item deveria ser TAG-NEW, obtido %s", response[0].UID)
	}
}

func TestRegisterFromPending_CreatesUserAndHardDeletesPending(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newTestHandler(t)

	pending := models.PendingRegistration{UID: "TAG-003", AttemptCount: 2, LastSeen: time.Now()}
	if err := db.Create(&pending).Error; err != nil {
		t.Fatalf("erro ao inserir pendência: %v", err)
	}

	router := gin.New()
	router.POST("/v1/users/register", handler.RegisterFromPending)

	w := postJSON(t, router, "/v1/users/register", models.CreateUserRequest{UID: "TAG-003", Name: "Paulo"})
	if w.Code != http.StatusCreated {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusCreated, w.Code)
	}

	var user models.User
	if err := db.Where("uid = ?", "TAG-003").First(&user).Error; err != nil {
		t.Fatalf("usuário não criado: %v", err)
	}
	if !user.Active {
		t.Fatalf("usuário deveria estar ativo")
	}

	var pendingCount int64
	if err := db.Unscoped().Model(&models.PendingRegistration{}).Where("uid = ?", "TAG-003").Count(&pendingCount).Error; err != nil {
		t.Fatalf("erro ao verificar remoção da pendência: %v", err)
	}
	if pendingCount != 0 {
		t.Fatalf("pendência deveria ter sido removida fisicamente, mas ainda existem %d registros", pendingCount)
	}
}

func TestRegisterFromPending_InvalidPayloadReturnsBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _ := newTestHandler(t)

	router := gin.New()
	router.POST("/v1/users/register", handler.RegisterFromPending)

	req := httptest.NewRequest(http.MethodPost, "/v1/users/register", bytes.NewBufferString(`{"uid":"TAG-004"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusBadRequest, w.Code)
	}
}

func TestRegisterFromPending_DuplicateUserReturnsConflict(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newTestHandler(t)

	if err := db.Create(&models.User{UID: "TAG-005", Name: "Existente", Active: true}).Error; err != nil {
		t.Fatalf("erro ao preparar usuário existente: %v", err)
	}
	if err := db.Create(&models.PendingRegistration{UID: "TAG-005", AttemptCount: 1, LastSeen: time.Now()}).Error; err != nil {
		t.Fatalf("erro ao preparar pendência: %v", err)
	}

	router := gin.New()
	router.POST("/v1/users/register", handler.RegisterFromPending)

	w := postJSON(t, router, "/v1/users/register", models.CreateUserRequest{UID: "TAG-005", Name: "Novo Nome"})
	if w.Code != http.StatusConflict {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusConflict, w.Code)
	}
}

func TestHandleAccessRequest_AuthorizedUserGetsAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newTestHandler(t)

	if err := db.Create(&models.User{UID: "TAG-AUTH", Name: "Paulo Autorizado", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar usuário autorizado: %v", err)
	}

	router := gin.New()
	router.POST("/v1/access", handler.HandleAccessRequest)

	w := postJSON(t, router, "/v1/access", buildAccessRequest("TAG-AUTH", "nonce-auth-1"))
	if w.Code != http.StatusOK {
		t.Fatalf("status inesperado: esperado %d, obtido %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response models.AccessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("erro ao desserializar resposta: %v", err)
	}
	if response.Status != "authorized" {
		t.Fatalf("status na resposta inesperado: esperado 'authorized', obtido '%s'", response.Status)
	}
	if response.User != "Paulo Autorizado" {
		t.Fatalf("nome do usuário inesperado: esperado 'Paulo Autorizado', obtido '%s'", response.User)
	}

	var auditLog models.AccessLog
	if err := db.Where("uid = ? AND status = ?", "TAG-AUTH", "authorized").First(&auditLog).Error; err != nil {
		t.Fatalf("log de auditoria de acesso autorizado não encontrado: %v", err)
	}
}

func TestHandleAccessRequest_InvalidSignatureDeniesAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newTestHandler(t)

	if err := db.Create(&models.User{UID: "TAG-BADSIG", Name: "Test", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar usuário: %v", err)
	}

	router := gin.New()
	router.POST("/v1/access", handler.HandleAccessRequest)

	invalidReq := models.AccessRequest{
		UID:       "TAG-BADSIG",
		Timestamp: time.Now().Unix(),
		Nonce:     "nonce-bad",
		Signature: "invalid-signature-xxxx",
	}

	w := postJSON(t, router, "/v1/access", invalidReq)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusUnauthorized, w.Code)
	}

	var auditLog models.AccessLog
	if err := db.Where("uid = ? AND message = ?", "TAG-BADSIG", "Assinatura Inválida").First(&auditLog).Error; err != nil {
		t.Fatalf("log de auditoria de assinatura inválida não encontrado: %v", err)
	}
}

func TestHandleAccessRequest_ReplayDetected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newTestHandler(t)

	if err := db.Create(&models.User{UID: "TAG-REPLAY", Name: "Test", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar usuário: %v", err)
	}

	router := gin.New()
	router.POST("/v1/access", handler.HandleAccessRequest)

	req := buildAccessRequest("TAG-REPLAY", "nonce-replay-1")
	w1 := postJSON(t, router, "/v1/access", req)
	if w1.Code != http.StatusOK {
		t.Fatalf("primeira requisição deveria ser aceita: status %d", w1.Code)
	}

	w2 := postJSON(t, router, "/v1/access", req)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("segunda requisição (replay) deveria ser rejeitada: esperado %d, obtido %d", http.StatusUnauthorized, w2.Code)
	}

	var auditLog models.AccessLog
	if err := db.Where("uid = ? AND message = ?", "TAG-REPLAY", "Replay detectado").First(&auditLog).Error; err != nil {
		t.Fatalf("log de auditoria de replay não encontrado: %v", err)
	}
}

func TestHandleAccessRequest_InvalidTimestamp(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _ := newTestHandler(t)

	router := gin.New()
	router.POST("/v1/access", handler.HandleAccessRequest)

	oldTimestamp := time.Now().Add(-5 * time.Minute).Unix()
	signature := sign("TAG-OLDTS", oldTimestamp, "nonce-old", testSecret)

	w := postJSON(t, router, "/v1/access", models.AccessRequest{
		UID:       "TAG-OLDTS",
		Timestamp: oldTimestamp,
		Nonce:     "nonce-old",
		Signature: signature,
	})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusUnauthorized, w.Code)
	}
}
