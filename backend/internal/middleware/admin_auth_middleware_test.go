package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/auth"
)

const middlewareSecret = "middleware-test-secret"

func buildAccessToken(t *testing.T, subject, username, role string) string {
	t.Helper()
	token, _, _, err := auth.GenerateAdminToken(middlewareSecret, subject, username, role, "access", 15*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("erro ao gerar token de teste: %v", err)
	}
	return token
}

func TestRequireAdminAuth_WithoutTokenReturnsUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/secure", RequireAdminAuth(middlewareSecret), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusUnauthorized, w.Code)
	}
}

func TestRequireAdminAuth_WithValidTokenSetsContext(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/secure", RequireAdminAuth(middlewareSecret), func(c *gin.Context) {
		if _, ok := c.Get(AdminUserIDContextKey); !ok {
			t.Fatalf("admin_user_id deveria estar presente no contexto")
		}
		if roleValue, ok := c.Get(AdminRoleContextKey); !ok || roleValue.(string) != "admin" {
			t.Fatalf("papel admin deveria estar presente no contexto")
		}
		c.Status(http.StatusOK)
	})

	token := buildAccessToken(t, "1", "admin", "admin")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusOK, w.Code)
	}
}

func TestRequireAdminRoles_RejectsForbiddenRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/secure",
		RequireAdminAuth(middlewareSecret),
		RequireAdminRoles("admin"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	token := buildAccessToken(t, "2", "viewer-user", "viewer")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusForbidden, w.Code)
	}
}

func TestRequireAdminRoles_AllowsConfiguredRole(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/secure",
		RequireAdminAuth(middlewareSecret),
		RequireAdminRoles("admin", "viewer"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	token := buildAccessToken(t, "2", "viewer-user", "viewer")
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status inesperado: esperado %d, obtido %d", http.StatusOK, w.Code)
	}
}
