package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newHealthTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("erro ao abrir banco de teste: %v", err)
	}

	if err := db.AutoMigrate(&models.AdminRefreshSession{}, &models.AdminAuditLog{}); err != nil {
		t.Fatalf("erro ao migrar modelos: %v", err)
	}

	return db
}

func TestSecurityHealthCheck_ReturnsOperationalCounters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newHealthTestDB(t)
	handler := NewHealthHandler(db)

	now := time.Now()
	if err := db.Create(&models.AdminRefreshSession{AdminUserID: 1, TokenHash: "active-hash", JTI: "active-jti", IssuedAt: now.Add(-10 * time.Minute), ExpiresAt: now.Add(10 * time.Minute)}).Error; err != nil {
		t.Fatalf("erro ao criar sessao ativa: %v", err)
	}
	if err := db.Create(&models.AdminRefreshSession{AdminUserID: 2, TokenHash: "expired-hash", JTI: "expired-jti", IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-1 * time.Hour)}).Error; err != nil {
		t.Fatalf("erro ao criar sessao expirada: %v", err)
	}
	if err := db.Create(&models.AdminAuditLog{Action: "admin.auth.login", Status: "failed", CreatedAt: now.Add(-2 * time.Hour)}).Error; err != nil {
		t.Fatalf("erro ao criar auditoria falha: %v", err)
	}

	router := gin.New()
	router.GET("/health/security", handler.HandleSecurityHealthCheck)

	req := httptest.NewRequest(http.MethodGet, "/health/security", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status inesperado: esperado %d, obtido %d, body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	var response models.SecurityHealthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("erro ao desserializar resposta: %v", err)
	}
	if response.ActiveAdminSessions != 1 {
		t.Fatalf("contagem de sessoes ativas incorreta: %d", response.ActiveAdminSessions)
	}
	if response.RecentFailedAdminAuth != 1 {
		t.Fatalf("contagem de falhas recentes incorreta: %d", response.RecentFailedAdminAuth)
	}
	if response.ExpiredRefreshSessions != 1 {
		t.Fatalf("contagem de sessoes expiradas incorreta: %d", response.ExpiredRefreshSessions)
	}
}
