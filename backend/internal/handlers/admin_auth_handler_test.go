package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"github.com/paulochiaradia/esp32-secure-access/internal/auth"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"github.com/paulochiaradia/esp32-secure-access/internal/repositories"
	"github.com/paulochiaradia/esp32-secure-access/internal/services"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newAdminAuthTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("erro ao abrir banco de teste: %v", err)
	}

	err = db.AutoMigrate(&models.AdminUser{}, &models.AdminRefreshSession{}, &models.AdminAuditLog{})
	if err != nil {
		t.Fatalf("erro ao migrar modelos admin: %v", err)
	}

	return db
}

func newAdminAuthTestHandler(t *testing.T) (*AdminAuthHandler, *gorm.DB) {
	t.Helper()

	db := newAdminAuthTestDB(t)
	service := services.NewAdminAuthService(db, repositories.NewAdminUserRepository(db), testSecret, 15*time.Minute, 7*24*time.Hour)
	return NewAdminAuthHandler(service), db
}

func TestAdminAuthLogin_SuccessReturnsTokensAndStoresRefreshSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newAdminAuthTestHandler(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("admin-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("erro ao gerar hash da senha: %v", err)
	}

	if err := db.Create(&models.AdminUser{Username: "admin", PasswordHash: string(hash), Role: "admin", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar admin: %v", err)
	}

	router := gin.New()
	router.POST("/v1/admin/auth/login", handler.Login)

	body, _ := json.Marshal(models.AdminLoginRequest{Username: "admin", Password: "admin-password"})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-agent")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status inesperado: esperado %d, obtido %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response models.AdminLoginResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("erro ao desserializar resposta: %v", err)
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		t.Fatalf("tokens nao foram retornados corretamente")
	}
	if response.User.Username != "admin" || response.User.Role != "admin" {
		t.Fatalf("dados do usuario retornados incorretamente")
	}

	var storedSession models.AdminRefreshSession
	if err := db.Where("token_hash = ?", auth.HashToken(response.RefreshToken)).First(&storedSession).Error; err != nil {
		t.Fatalf("sessao refresh nao foi criada: %v", err)
	}
	if storedSession.TokenHash == "" || storedSession.RevokedAt != nil {
		t.Fatalf("sessao refresh armazenada invalida")
	}
	if storedSession.UserAgent != "test-agent" {
		t.Fatalf("user agent nao foi persistido corretamente")
	}
}

func TestAdminAuthLogin_InvalidPasswordReturnsUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newAdminAuthTestHandler(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("admin-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("erro ao gerar hash da senha: %v", err)
	}

	if err := db.Create(&models.AdminUser{Username: "admin", PasswordHash: string(hash), Role: "admin", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar admin: %v", err)
	}

	router := gin.New()
	router.POST("/v1/admin/auth/login", handler.Login)

	body, _ := json.Marshal(models.AdminLoginRequest{Username: "admin", Password: "senha-errada"})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusUnauthorized, w.Code)
	}
}

func TestAdminAuthRefresh_RotatesSessionAndRevokesPreviousToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newAdminAuthTestHandler(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("admin-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("erro ao gerar hash da senha: %v", err)
	}

	if err := db.Create(&models.AdminUser{Username: "admin", PasswordHash: string(hash), Role: "admin", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar admin: %v", err)
	}

	router := gin.New()
	router.POST("/v1/admin/auth/login", handler.Login)
	router.POST("/v1/admin/auth/refresh", handler.Refresh)

	loginBody, _ := json.Marshal(models.AdminLoginRequest{Username: "admin", Password: "admin-password"})
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("User-Agent", "login-agent")
	loginRes := httptest.NewRecorder()
	router.ServeHTTP(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("login falhou: %d %s", loginRes.Code, loginRes.Body.String())
	}

	var loginResponse models.AdminLoginResponse
	if err := json.Unmarshal(loginRes.Body.Bytes(), &loginResponse); err != nil {
		t.Fatalf("erro ao desserializar login: %v", err)
	}

	refreshBody, _ := json.Marshal(models.AdminRefreshRequest{RefreshToken: loginResponse.RefreshToken})
	refreshReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/refresh", bytes.NewBuffer(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshReq.Header.Set("User-Agent", "refresh-agent")
	refreshRes := httptest.NewRecorder()
	router.ServeHTTP(refreshRes, refreshReq)

	if refreshRes.Code != http.StatusOK {
		t.Fatalf("refresh falhou: %d %s", refreshRes.Code, refreshRes.Body.String())
	}

	var refreshResponse models.AdminLoginResponse
	if err := json.Unmarshal(refreshRes.Body.Bytes(), &refreshResponse); err != nil {
		t.Fatalf("erro ao desserializar refresh: %v", err)
	}
	if refreshResponse.RefreshToken == "" || refreshResponse.RefreshToken == loginResponse.RefreshToken {
		t.Fatalf("refresh token nao foi rotacionado")
	}

	var oldSession models.AdminRefreshSession
	if err := db.Where("token_hash = ?", auth.HashToken(loginResponse.RefreshToken)).First(&oldSession).Error; err != nil {
		t.Fatalf("sessao antiga nao encontrada: %v", err)
	}
	if oldSession.RevokedAt == nil || oldSession.ReplacedBySessionID == nil {
		t.Fatalf("sessao antiga nao foi revogada corretamente")
	}

	var newSession models.AdminRefreshSession
	if err := db.Where("token_hash = ?", auth.HashToken(refreshResponse.RefreshToken)).First(&newSession).Error; err != nil {
		t.Fatalf("nova sessao nao encontrada: %v", err)
	}
	if newSession.RevokedAt != nil {
		t.Fatalf("nova sessao nao deveria estar revogada")
	}

	reuseReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/refresh", bytes.NewBuffer(refreshBody))
	reuseReq.Header.Set("Content-Type", "application/json")
	reuseRes := httptest.NewRecorder()
	router.ServeHTTP(reuseRes, reuseReq)
	if reuseRes.Code != http.StatusUnauthorized {
		t.Fatalf("reuso do refresh antigo deveria retornar 401, obtido %d", reuseRes.Code)
	}
}

func TestAdminAuthRefresh_InvalidTokenReturnsUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, _ := newAdminAuthTestHandler(t)

	router := gin.New()
	router.POST("/v1/admin/auth/refresh", handler.Refresh)

	body, _ := json.Marshal(models.AdminRefreshRequest{RefreshToken: "token-invalido"})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/refresh", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusUnauthorized, w.Code)
	}
}
