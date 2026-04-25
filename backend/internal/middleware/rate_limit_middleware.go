package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type rateWindow struct {
	count       int
	windowStart time.Time
}

// FixedWindowRateLimiter aplica limite por chave em uma janela fixa de tempo.
type FixedWindowRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateWindow
}

func NewFixedWindowRateLimiter() *FixedWindowRateLimiter {
	return &FixedWindowRateLimiter{entries: make(map[string]*rateWindow)}
}

// LimitByKey limita requisições por chave usando uma janela fixa.
func (l *FixedWindowRateLimiter) LimitByKey(maxRequests int, window time.Duration, keyFunc func(*gin.Context) string) gin.HandlerFunc {
	if maxRequests <= 0 {
		maxRequests = 1
	}
	if window <= 0 {
		window = time.Minute
	}

	return func(c *gin.Context) {
		key := keyFunc(c)
		if key == "" {
			key = "anonymous"
		}

		now := time.Now()

		l.mu.Lock()
		entry, exists := l.entries[key]
		if !exists || now.Sub(entry.windowStart) >= window {
			entry = &rateWindow{count: 0, windowStart: now}
			l.entries[key] = entry
		}

		if entry.count >= maxRequests {
			retryAfter := int(window.Seconds()) - int(now.Sub(entry.windowStart).Seconds())
			if retryAfter < 1 {
				retryAfter = 1
			}
			l.mu.Unlock()

			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"status":  "error",
				"message": "Muitas requisições. Tente novamente em instantes",
			})
			return
		}

		entry.count++
		l.mu.Unlock()

		c.Next()
	}
}