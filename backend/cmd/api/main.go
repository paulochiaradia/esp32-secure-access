package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/config"
	"github.com/paulochiaradia/esp32-secure-access/internal/database"
	"github.com/paulochiaradia/esp32-secure-access/internal/handlers"
	"github.com/paulochiaradia/esp32-secure-access/internal/middleware"
	"github.com/paulochiaradia/esp32-secure-access/internal/repositories"
	"github.com/paulochiaradia/esp32-secure-access/internal/services"
)

func main() {
	cfg, err := config.GetConfig()
	if err != nil {
		log.Fatalf("falha de configuração: %v", err)
	}

	db := database.Init(cfg.DBPath)

	userRepository := repositories.NewUserRepository(db)
	adminUserRepository := repositories.NewAdminUserRepository(db)
	accessLogRepository := repositories.NewAccessLogRepository(db)
	nonceRepository := repositories.NewNonceRepository(db)
	accessService := services.NewAccessService(
		cfg.SecretKey,
		userRepository,
		accessLogRepository,
		nonceRepository,
		time.Duration(cfg.AllowedClockSkewSeconds)*time.Second,
		time.Duration(cfg.NonceTTLSeconds)*time.Second,
	)
	adminAuthService := services.NewAdminAuthService(
		db,
		adminUserRepository,
		cfg.SecretKey,
		15*time.Minute,
		7*24*time.Hour,
	)
	rateLimiter := middleware.NewFixedWindowRateLimiter()
	accessHandler := handlers.NewAccessHandler(accessService, db)
	adminAuthHandler := handlers.NewAdminAuthHandler(adminAuthService)
	healthHandler := handlers.NewHealthHandler(db)

	go func() {
		for {
			time.Sleep(10 * time.Minute)
			if err := database.CleanOldPendingRegistrations(db); err != nil {
				log.Printf("Erro na limpeza de pendências: %v", err)
			} else {
				log.Println("Limpeza de tags pendentes executada com sucesso.")
			}
		}
	}()

	r := gin.Default()
	r.GET("/health", healthHandler.HandleHealthCheck)
	v1 := r.Group("/v1")
	{
		v1.POST("/access", accessHandler.HandleAccessRequest)

		adminAuth := v1.Group("/admin/auth")
		{
			adminAuth.POST("/login", rateLimiter.LimitByKey(5, time.Minute, func(c *gin.Context) string { return c.ClientIP() }), adminAuthHandler.Login)
			adminAuth.POST("/refresh", rateLimiter.LimitByKey(20, time.Minute, func(c *gin.Context) string { return c.ClientIP() }), adminAuthHandler.Refresh)
		}

		admin := v1.Group("/admin")
		admin.Use(middleware.RequireAdminAuth(cfg.SecretKey))
		admin.Use(rateLimiter.LimitByKey(60, time.Minute, func(c *gin.Context) string {
			if userID, ok := c.Get(middleware.AdminUserIDContextKey); ok {
				return fmt.Sprintf("admin:%v", userID)
			}
			return "admin:" + c.ClientIP()
		}))
		{
			admin.GET("/users/pending", middleware.RequireAdminRoles("admin", "viewer"), accessHandler.ListPending)
			admin.POST("/users/register", middleware.RequireAdminRoles("admin"), accessHandler.RegisterFromPending)
		}
	}

	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("falha ao subir servidor: %v", err)
	}
}
