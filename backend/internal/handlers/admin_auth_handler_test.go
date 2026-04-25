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
	"github.com/paulochiaradia/esp32-secure-access/internal/middleware"
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
	return NewAdminAuthHandler(service, "bootstrap-token"), db
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

	var loginAudit models.AdminAuditLog
	if err := db.Where("action = ? AND status = ?", "admin.auth.login", "success").First(&loginAudit).Error; err != nil {
		t.Fatalf("auditoria de login com sucesso nao encontrada: %v", err)
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

	var failAudit models.AdminAuditLog
	if err := db.Where("action = ? AND status = ?", "admin.auth.login", "failed").First(&failAudit).Error; err != nil {
		t.Fatalf("auditoria de login com falha nao encontrada: %v", err)
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

	var refreshSuccessAudit models.AdminAuditLog
	if err := db.Where("action = ? AND status = ?", "admin.auth.refresh", "success").First(&refreshSuccessAudit).Error; err != nil {
		t.Fatalf("auditoria de refresh com sucesso nao encontrada: %v", err)
	}

	reuseReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/refresh", bytes.NewBuffer(refreshBody))
	reuseReq.Header.Set("Content-Type", "application/json")
	reuseRes := httptest.NewRecorder()
	router.ServeHTTP(reuseRes, reuseReq)
	if reuseRes.Code != http.StatusUnauthorized {
		t.Fatalf("reuso do refresh antigo deveria retornar 401, obtido %d", reuseRes.Code)
	}

	var refreshFailedAudit models.AdminAuditLog
	if err := db.Where("action = ? AND status = ?", "admin.auth.refresh", "failed").First(&refreshFailedAudit).Error; err != nil {
		t.Fatalf("auditoria de refresh com falha nao encontrada: %v", err)
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

func TestAdminAuthBootstrap_CreatesFirstAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newAdminAuthTestHandler(t)

	router := gin.New()
	router.POST("/v1/admin/auth/bootstrap", handler.Bootstrap)

	body, _ := json.Marshal(models.AdminBootstrapRequest{Username: "root-admin", Password: "super-secret-password", Role: "admin"})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/bootstrap", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Bootstrap-Token", "bootstrap-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status inesperado: esperado %d, obtido %d, body: %s", http.StatusCreated, w.Code, w.Body.String())
	}

	var admin models.AdminUser
	if err := db.Where("username = ?", "root-admin").First(&admin).Error; err != nil {
		t.Fatalf("admin bootstrap nao foi criado: %v", err)
	}
}

func TestAdminAuthLogout_RevokesRefreshSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newAdminAuthTestHandler(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("admin-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("erro ao gerar hash da senha: %v", err)
	}
	if err := db.Create(&models.AdminUser{Username: "admin-logout", PasswordHash: string(hash), Role: "admin", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar admin: %v", err)
	}

	router := gin.New()
	router.POST("/v1/admin/auth/login", handler.Login)
	router.POST("/v1/admin/auth/refresh", handler.Refresh)
	protected := router.Group("/v1/admin/auth")
	protected.Use(middleware.RequireAdminAuth(testSecret))
	protected.POST("/logout", handler.Logout)

	loginBody, _ := json.Marshal(models.AdminLoginRequest{Username: "admin-logout", Password: "admin-password"})
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes := httptest.NewRecorder()
	router.ServeHTTP(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("login falhou: %d %s", loginRes.Code, loginRes.Body.String())
	}

	var loginResponse models.AdminLoginResponse
	if err := json.Unmarshal(loginRes.Body.Bytes(), &loginResponse); err != nil {
		t.Fatalf("erro ao desserializar login: %v", err)
	}

	logoutBody, _ := json.Marshal(models.AdminLogoutRequest{RefreshToken: loginResponse.RefreshToken})
	logoutReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/logout", bytes.NewBuffer(logoutBody))
	logoutReq.Header.Set("Content-Type", "application/json")
	logoutReq.Header.Set("Authorization", "Bearer "+loginResponse.AccessToken)
	logoutRes := httptest.NewRecorder()
	router.ServeHTTP(logoutRes, logoutReq)

	if logoutRes.Code != http.StatusNoContent {
		t.Fatalf("logout deveria retornar 204, retornou %d", logoutRes.Code)
	}

	refreshBody, _ := json.Marshal(models.AdminRefreshRequest{RefreshToken: loginResponse.RefreshToken})
	refreshReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/refresh", bytes.NewBuffer(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshRes := httptest.NewRecorder()
	router.ServeHTTP(refreshRes, refreshReq)
	if refreshRes.Code != http.StatusUnauthorized {
		t.Fatalf("refresh após logout deveria retornar 401, retornou %d", refreshRes.Code)
	}
}

func TestAdminAuthChangePassword_UpdatesCredentialsAndRevokesSessions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newAdminAuthTestHandler(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("admin-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("erro ao gerar hash da senha: %v", err)
	}
	if err := db.Create(&models.AdminUser{Username: "admin-change", PasswordHash: string(hash), Role: "admin", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar admin: %v", err)
	}

	router := gin.New()
	router.POST("/v1/admin/auth/login", handler.Login)
	protected := router.Group("/v1/admin/auth")
	protected.Use(middleware.RequireAdminAuth(testSecret))
	protected.POST("/change-password", handler.ChangePassword)

	loginBody, _ := json.Marshal(models.AdminLoginRequest{Username: "admin-change", Password: "admin-password"})
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes := httptest.NewRecorder()
	router.ServeHTTP(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("login inicial falhou: %d", loginRes.Code)
	}

	var loginResponse models.AdminLoginResponse
	if err := json.Unmarshal(loginRes.Body.Bytes(), &loginResponse); err != nil {
		t.Fatalf("erro ao desserializar login inicial: %v", err)
	}

	changeBody, _ := json.Marshal(models.AdminChangePasswordRequest{CurrentPassword: "admin-password", NewPassword: "admin-password-2"})
	changeReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/change-password", bytes.NewBuffer(changeBody))
	changeReq.Header.Set("Content-Type", "application/json")
	changeReq.Header.Set("Authorization", "Bearer "+loginResponse.AccessToken)
	changeRes := httptest.NewRecorder()
	router.ServeHTTP(changeRes, changeReq)

	if changeRes.Code != http.StatusOK {
		t.Fatalf("change-password deveria retornar 200, retornou %d", changeRes.Code)
	}

	oldLoginBody, _ := json.Marshal(models.AdminLoginRequest{Username: "admin-change", Password: "admin-password"})
	oldLoginReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(oldLoginBody))
	oldLoginReq.Header.Set("Content-Type", "application/json")
	oldLoginRes := httptest.NewRecorder()
	router.ServeHTTP(oldLoginRes, oldLoginReq)
	if oldLoginRes.Code != http.StatusUnauthorized {
		t.Fatalf("login com senha antiga deveria retornar 401, retornou %d", oldLoginRes.Code)
	}

	newLoginBody, _ := json.Marshal(models.AdminLoginRequest{Username: "admin-change", Password: "admin-password-2"})
	newLoginReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(newLoginBody))
	newLoginReq.Header.Set("Content-Type", "application/json")
	newLoginRes := httptest.NewRecorder()
	router.ServeHTTP(newLoginRes, newLoginReq)
	if newLoginRes.Code != http.StatusOK {
		t.Fatalf("login com senha nova deveria retornar 200, retornou %d", newLoginRes.Code)
	}
}

func TestAdminAuthRevokeAllSessions_RevokesTargetUserSessions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	handler, db := newAdminAuthTestHandler(t)

	hash, err := bcrypt.GenerateFromPassword([]byte("admin-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("erro ao gerar hash da senha: %v", err)
	}
	if err := db.Create(&models.AdminUser{Username: "admin-revoke", PasswordHash: string(hash), Role: "admin", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar admin: %v", err)
	}

	router := gin.New()
	router.POST("/v1/admin/auth/login", handler.Login)
	router.POST("/v1/admin/auth/refresh", handler.Refresh)
	protected := router.Group("/v1/admin/auth")
	protected.Use(middleware.RequireAdminAuth(testSecret))
	protected.POST("/revoke-all-sessions", handler.RevokeAllSessions)

	loginBody, _ := json.Marshal(models.AdminLoginRequest{Username: "admin-revoke", Password: "admin-password"})
	loginReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes := httptest.NewRecorder()
	router.ServeHTTP(loginRes, loginReq)
	if loginRes.Code != http.StatusOK {
		t.Fatalf("login inicial falhou: %d", loginRes.Code)
	}

	var loginResponse models.AdminLoginResponse
	if err := json.Unmarshal(loginRes.Body.Bytes(), &loginResponse); err != nil {
		t.Fatalf("erro ao desserializar login inicial: %v", err)
	}

	revokeBody, _ := json.Marshal(models.AdminRevokeSessionsRequest{})
	revokeReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/revoke-all-sessions", bytes.NewBuffer(revokeBody))
	revokeReq.Header.Set("Content-Type", "application/json")
	revokeReq.Header.Set("Authorization", "Bearer "+loginResponse.AccessToken)
	revokeRes := httptest.NewRecorder()
	router.ServeHTTP(revokeRes, revokeReq)
	if revokeRes.Code != http.StatusOK {
		t.Fatalf("revoke-all-sessions deveria retornar 200, retornou %d", revokeRes.Code)
	}

	refreshBody, _ := json.Marshal(models.AdminRefreshRequest{RefreshToken: loginResponse.RefreshToken})
	refreshReq := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/refresh", bytes.NewBuffer(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshRes := httptest.NewRecorder()
	router.ServeHTTP(refreshRes, refreshReq)
	if refreshRes.Code != http.StatusUnauthorized {
		t.Fatalf("refresh após revoke-all deveria retornar 401, retornou %d", refreshRes.Code)
	}
}
