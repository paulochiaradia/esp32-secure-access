package main

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/config"
	"github.com/paulochiaradia/esp32-secure-access/internal/database"
	"github.com/paulochiaradia/esp32-secure-access/internal/handlers"
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
		v1.POST("/admin/auth/login", adminAuthHandler.Login)
		v1.GET("/users/pending", accessHandler.ListPending)
		v1.POST("/users/register", accessHandler.RegisterFromPending)
	}

	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("falha ao subir servidor: %v", err)
	}
}
