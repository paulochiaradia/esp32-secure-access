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
	accessHandler := handlers.NewAccessHandler(accessService)
	healthHandler := handlers.NewHealthHandler(db)

	r := gin.Default()
	r.GET("/health", healthHandler.HandleHealthCheck)
	v1 := r.Group("/v1")
	{
		v1.POST("/access", accessHandler.HandleAccessRequest)
	}

	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("falha ao subir servidor: %v", err)
	}
}
