package config

import (
	"os"
	"sync"

	"github.com/joho/godotenv"
)

type Config struct {
	SecretKey string
	Port      string
	DBPath    string
}

var (
	once   sync.Once
	config *Config
)

// GetConfig retorna a instância única das configurações (Singleton)
func GetConfig() *Config {
	once.Do(func() {
		// Tenta carregar o .env, mas não morre se não existir (útil para produção/Docker)
		_ = godotenv.Load("../../.env")

		config = &Config{
			SecretKey: getEnv("SECRET_KEY", "mudar-em-producao"),
			Port:      getEnv("PORT", "8080"),
			DBPath:    getEnv("DB_PATH", "access_control.db"),
		}
	})
	return config
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}