package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	"gorm.io/gorm"
)

func newProtectedAdminRouter(t *testing.T, db *gorm.DB) *gin.Engine {
	t.Helper()

	accessService := services.NewAccessService(
		testSecret,
		repositories.NewUserRepository(db),
		repositories.NewAccessLogRepository(db),
		repositories.NewNonceRepository(db),
		2*time.Minute,
		5*time.Minute,
	)
	adminAuthService := services.NewAdminAuthService(
		db,
		repositories.NewAdminUserRepository(db),
		testSecret,
		15*time.Minute,
		7*24*time.Hour,
	)

	accessHandler := NewAccessHandler(accessService, db)
	adminAuthHandler := NewAdminAuthHandler(adminAuthService, "bootstrap-token")
	rateLimiter := middleware.NewFixedWindowRateLimiter()

	r := gin.New()
	v1 := r.Group("/v1")
	{
		adminAuth := v1.Group("/admin/auth")
		{
			adminAuth.POST("/login", rateLimiter.LimitByKey(5, time.Minute, func(c *gin.Context) string { return c.ClientIP() }), adminAuthHandler.Login)
			adminAuth.POST("/refresh", rateLimiter.LimitByKey(20, time.Minute, func(c *gin.Context) string { return c.ClientIP() }), adminAuthHandler.Refresh)
		}

		admin := v1.Group("/admin")
		admin.Use(middleware.RequireAdminAuth(testSecret))
		admin.Use(rateLimiter.LimitByKey(60, time.Minute, func(c *gin.Context) string {
			if userID, ok := c.Get(middleware.AdminUserIDContextKey); ok {
				return fmt.Sprintf("admin:user:%v", userID)
			}
			return "admin:ip:" + c.ClientIP()
		}))
		{
			admin.GET("/users/pending", middleware.RequireAdminRoles("admin", "viewer"), accessHandler.ListPending)
			admin.POST("/users/register", middleware.RequireAdminRoles("admin"), accessHandler.RegisterFromPending)
			admin.GET("/audit", middleware.RequireAdminRoles("admin"), accessHandler.ListAuditLogs)
		}
	}

	return r
}

func buildAccessTokenForRole(t *testing.T, userID, username, role string) string {
	t.Helper()

	token, _, _, err := auth.GenerateAdminToken(testSecret, userID, username, role, "access", 15*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("erro ao gerar access token: %v", err)
	}
	return token
}

func TestAdminProtectedRoutes_WithoutTokenReturnsUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestDB(t)
	router := newProtectedAdminRouter(t, db)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users/pending", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusUnauthorized, w.Code)
	}

	var response models.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("erro ao desserializar resposta: %v", err)
	}
	if response.Code != "AUTH_TOKEN_MISSING" || response.TraceID == "" {
		t.Fatalf("resposta de erro nao padronizada: %+v", response)
	}
}

func TestAdminProtectedRoutes_ViewerCannotRegister(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestDB(t)
	router := newProtectedAdminRouter(t, db)

	token := buildAccessTokenForRole(t, "10", "viewer-user", "viewer")
	payload, _ := json.Marshal(models.CreateUserRequest{UID: "TAG-ROLE-01", Name: "Viewer"})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/users/register", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusForbidden, w.Code)
	}

	var response models.ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("erro ao desserializar resposta: %v", err)
	}
	if response.Code != "AUTH_FORBIDDEN" || response.TraceID == "" {
		t.Fatalf("resposta de erro nao padronizada: %+v", response)
	}
}

func TestAdminProtectedRoutes_AdminCanListPending(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestDB(t)
	router := newProtectedAdminRouter(t, db)

	if err := db.Create(&models.PendingRegistration{UID: "TAG-PENDING-1", AttemptCount: 1, LastSeen: time.Now()}).Error; err != nil {
		t.Fatalf("erro ao criar pendencia: %v", err)
	}

	token := buildAccessTokenForRole(t, "1", "admin-user", "admin")
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users/pending", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusOK, w.Code)
	}
}

func TestAdminAuthLogin_RateLimitByIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestDB(t)
	router := newProtectedAdminRouter(t, db)

	hash, err := bcrypt.GenerateFromPassword([]byte("admin-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("erro ao gerar hash de senha: %v", err)
	}
	if err := db.Create(&models.AdminUser{Username: "admin-login", PasswordHash: string(hash), Role: "admin", Active: true}).Error; err != nil {
		t.Fatalf("erro ao criar admin de teste: %v", err)
	}

	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(models.AdminLoginRequest{Username: "admin-login", Password: "senha-errada"})
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("tentativa %d deveria retornar 401, retornou %d", i+1, w.Code)
		}
	}

	body, _ := json.Marshal(models.AdminLoginRequest{Username: "admin-login", Password: "senha-errada"})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/auth/login", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("sexta tentativa deveria retornar 429, retornou %d", w.Code)
	}
}

func TestAdminProtectedRoutes_TamperedAndExpiredTokensRejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestDB(t)
	router := newProtectedAdminRouter(t, db)

	tampered := buildAccessTokenForRole(t, "10", "viewer-user", "viewer")
	tampered = tampered[:len(tampered)-1] + "x"
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users/pending", nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("token adulterado deveria retornar 401, retornou %d", w.Code)
	}

	expired, _, _, err := auth.GenerateAdminToken(testSecret, "11", "expired-user", "admin", "access", -time.Minute, time.Now())
	if err != nil {
		t.Fatalf("erro ao gerar token expirado: %v", err)
	}
	expiredReq := httptest.NewRequest(http.MethodGet, "/v1/admin/users/pending", nil)
	expiredReq.Header.Set("Authorization", "Bearer "+expired)
	expiredRes := httptest.NewRecorder()
	router.ServeHTTP(expiredRes, expiredReq)
	if expiredRes.Code != http.StatusUnauthorized {
		t.Fatalf("token expirado deveria retornar 401, retornou %d", expiredRes.Code)
	}
}

func TestAdminProtectedRoutes_InvalidRoleIsForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestDB(t)
	router := newProtectedAdminRouter(t, db)

	token := buildAccessTokenForRole(t, "12", "guest-user", "guest")
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/users/pending", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("role invalida deveria retornar 403, retornou %d", w.Code)
	}
}

func TestAdminAuditLogs_FilterAndPaginate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newTestDB(t)
	router := newProtectedAdminRouter(t, db)

	base := time.Now()
	logs := []models.AdminAuditLog{
		{Action: "admin.auth.login", Status: "success", CreatedAt: base.Add(-2 * time.Hour)},
		{Action: "admin.auth.login", Status: "failed", CreatedAt: base.Add(-90 * time.Minute)},
		{Action: "admin.users.register", Status: "success", CreatedAt: base.Add(-30 * time.Minute)},
	}
	for i := range logs {
		if err := db.Create(&logs[i]).Error; err != nil {
			t.Fatalf("erro ao criar log %d: %v", i, err)
		}
	}

	token := buildAccessTokenForRole(t, "1", "admin-user", "admin")
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit?action=admin.auth.login&status=success&page=1&limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("audit endpoint deveria retornar 200, retornou %d, body: %s", w.Code, w.Body.String())
	}

	var response struct {
		Status     string                 `json:"status"`
		Data       []models.AdminAuditLog `json:"data"`
		Pagination map[string]interface{} `json:"pagination"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("erro ao desserializar auditoria: %v", err)
	}
	if len(response.Data) != 1 {
		t.Fatalf("filtro/paginacao deveria retornar 1 item, retornou %d", len(response.Data))
	}
	if response.Data[0].Action != "admin.auth.login" || response.Data[0].Status != "success" {
		t.Fatalf("resultado filtrado incorreto: %+v", response.Data[0])
	}
}
