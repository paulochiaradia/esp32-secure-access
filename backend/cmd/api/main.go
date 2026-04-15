package main

import (
	"github.com/gin-gonic/gin"
	"github.com/paulochiaradia/esp32-secure-access/internal/handlers"
)

func main() {
	r := gin.Default()

	// Agrupamento por versão da API
	v1 := r.Group("/v1")
	{
		v1.POST("/access", handlers.HandleAccessRequest)
	}

	r.Run(":8080")
}
