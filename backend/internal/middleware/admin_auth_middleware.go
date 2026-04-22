package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/auth"
)

const (
	AdminUserIDContextKey   = "admin_user_id"
	AdminUsernameContextKey = "admin_username"
	AdminRoleContextKey     = "admin_role"
)

// RequireAdminAuth valida o access token administrativo e injeta claims no contexto.
func RequireAdminAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := strings.TrimSpace(c.GetHeader("Authorization"))
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Token de acesso ausente"})
			return
		}

		tokenString := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		claims, err := auth.ParseAndValidateAdminToken(secret, tokenString, "access")
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Token de acesso inválido"})
			return
		}

		adminUserID, err := strconv.ParseUint(claims.Subject, 10, 64)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Token de acesso inválido"})
			return
		}

		c.Set(AdminUserIDContextKey, uint(adminUserID))
		c.Set(AdminUsernameContextKey, claims.Username)
		c.Set(AdminRoleContextKey, claims.Role)
		c.Next()
	}
}

// RequireAdminRoles restringe acesso por papel para rotas administrativas.
func RequireAdminRoles(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		allowed[role] = struct{}{}
	}

	return func(c *gin.Context) {
		roleValue, exists := c.Get(AdminRoleContextKey)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Token de acesso ausente"})
			return
		}

		role, ok := roleValue.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Token de acesso inválido"})
			return
		}

		if _, isAllowed := allowed[role]; !isAllowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"status": "error", "message": "Permissão insuficiente"})
			return
		}

		c.Next()
	}
}
