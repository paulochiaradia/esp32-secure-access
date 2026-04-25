package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestLimitByKey_ExceedsLimitReturnsTooManyRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewFixedWindowRateLimiter()

	router := gin.New()
	router.GET("/limited", limiter.LimitByKey(2, time.Minute, func(c *gin.Context) string {
		return "fixed-key"
	}), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/limited", nil)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("requisição %d deveria retornar 200, retornou %d", i+1, w.Code)
		}
	}

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/limited", nil)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("terceira requisição deveria retornar 429, retornou %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Fatalf("header Retry-After deveria estar presente")
	}
}

func TestLimitByKey_WindowResetAllowsNewRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	limiter := NewFixedWindowRateLimiter()

	router := gin.New()
	router.GET("/limited", limiter.LimitByKey(1, 20*time.Millisecond, func(c *gin.Context) string {
		return "fixed-key"
	}), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/limited", nil)
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("primeira requisição deveria retornar 200, retornou %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/limited", nil)
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("segunda requisição deveria retornar 429, retornou %d", w2.Code)
	}

	time.Sleep(25 * time.Millisecond)

	w3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/limited", nil)
	router.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("após reset da janela deveria retornar 200, retornou %d", w3.Code)
	}
}
