package main

import (
	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/config"
	"github.com/paulochiaradia/esp32-secure-access/internal/database"
	"github.com/paulochiaradia/esp32-secure-access/internal/handlers"
	"github.com/paulochiaradia/esp32-secure-access/internal/repositories"
	"github.com/paulochiaradia/esp32-secure-access/internal/services"
)

func main() {
	cfg := config.GetConfig()
	db := database.Init(cfg.DBPath)
	accessRepository := repositories.NewAccessRepository(db)
	accessService := services.NewAccessService(cfg.SecretKey, accessRepository)
	accessHandler := handlers.NewAccessHandler(accessService)
	healthHandler := handlers.NewHealthHandler()

	r := gin.Default()
	r.GET("/health", healthHandler.HandleHealthCheck)
	v1 := r.Group("/v1")
	{
		v1.POST("/access", accessHandler.HandleAccessRequest)
	}

	r.Run(":" + cfg.Port)
}
