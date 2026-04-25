package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/joho/godotenv"
)

type Config struct {
	SecretKey                      string
	Port                           string
	DBPath                         string
	AllowedClockSkewSeconds        int
	NonceTTLSeconds                int
	AdminAccessTokenTTLSeconds     int
	AdminRefreshTokenTTLSeconds    int
	AdminLoginRateLimitPerMinute   int
	AdminRefreshRateLimitPerMinute int
	AdminRoutesRateLimitPerMinute  int
	AdminBootstrapToken            string
}

var (
	once    sync.Once
	config  *Config
	loadErr error
)

// GetConfig retorna a instância única das configurações (Singleton)
func GetConfig() (*Config, error) {
	once.Do(func() {
		// Tenta carregar .env tanto no root quanto no backend.
		_ = godotenv.Load(".env")
		_ = godotenv.Load("../../.env")
		_ = godotenv.Load("backend/.env")

		allowedClockSkew, err := getEnvAsInt("ALLOWED_CLOCK_SKEW_SECONDS", 60)
		if err != nil {
			loadErr = err
			return
		}

		nonceTTL, err := getEnvAsInt("NONCE_TTL_SECONDS", 300)
		if err != nil {
			loadErr = err
			return
		}

		adminAccessTTL, err := getEnvAsInt("ADMIN_ACCESS_TOKEN_TTL_SECONDS", 900)
		if err != nil {
			loadErr = err
			return
		}

		adminRefreshTTL, err := getEnvAsInt("ADMIN_REFRESH_TOKEN_TTL_SECONDS", 604800)
		if err != nil {
			loadErr = err
			return
		}

		adminLoginRateLimit, err := getEnvAsInt("ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE", 5)
		if err != nil {
			loadErr = err
			return
		}

		adminRefreshRateLimit, err := getEnvAsInt("ADMIN_REFRESH_RATE_LIMIT_PER_MINUTE", 20)
		if err != nil {
			loadErr = err
			return
		}

		adminRoutesRateLimit, err := getEnvAsInt("ADMIN_ROUTES_RATE_LIMIT_PER_MINUTE", 60)
		if err != nil {
			loadErr = err
			return
		}

		config = &Config{
			SecretKey:                      getEnv("SECRET_KEY", ""),
			Port:                           getEnv("PORT", "8080"),
			DBPath:                         getEnv("DB_PATH", "access_control.db"),
			AllowedClockSkewSeconds:        allowedClockSkew,
			NonceTTLSeconds:                nonceTTL,
			AdminAccessTokenTTLSeconds:     adminAccessTTL,
			AdminRefreshTokenTTLSeconds:    adminRefreshTTL,
			AdminLoginRateLimitPerMinute:   adminLoginRateLimit,
			AdminRefreshRateLimitPerMinute: adminRefreshRateLimit,
			AdminRoutesRateLimitPerMinute:  adminRoutesRateLimit,
			AdminBootstrapToken:            getEnv("ADMIN_BOOTSTRAP_TOKEN", ""),
		}

		loadErr = validateConfig(config)
	})

	if loadErr != nil {
		return nil, loadErr
	}
	return config, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) (int, error) {
	value := getEnv(key, strconv.Itoa(defaultValue))
	parsedValue, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("valor inválido para %s: %w", key, err)
	}
	return parsedValue, nil
}

func validateConfig(cfg *Config) error {
	if strings.TrimSpace(cfg.SecretKey) == "" {
		return fmt.Errorf("SECRET_KEY é obrigatório")
	}
	if strings.TrimSpace(cfg.Port) == "" {
		return fmt.Errorf("PORT é obrigatório")
	}
	if strings.TrimSpace(cfg.DBPath) == "" {
		return fmt.Errorf("DB_PATH é obrigatório")
	}
	if cfg.AllowedClockSkewSeconds <= 0 {
		return fmt.Errorf("ALLOWED_CLOCK_SKEW_SECONDS deve ser maior que zero")
	}
	if cfg.NonceTTLSeconds <= 0 {
		return fmt.Errorf("NONCE_TTL_SECONDS deve ser maior que zero")
	}
	if cfg.AdminAccessTokenTTLSeconds <= 0 {
		return fmt.Errorf("ADMIN_ACCESS_TOKEN_TTL_SECONDS deve ser maior que zero")
	}
	if cfg.AdminRefreshTokenTTLSeconds <= 0 {
		return fmt.Errorf("ADMIN_REFRESH_TOKEN_TTL_SECONDS deve ser maior que zero")
	}
	if cfg.AdminLoginRateLimitPerMinute <= 0 {
		return fmt.Errorf("ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE deve ser maior que zero")
	}
	if cfg.AdminRefreshRateLimitPerMinute <= 0 {
		return fmt.Errorf("ADMIN_REFRESH_RATE_LIMIT_PER_MINUTE deve ser maior que zero")
	}
	if cfg.AdminRoutesRateLimitPerMinute <= 0 {
		return fmt.Errorf("ADMIN_ROUTES_RATE_LIMIT_PER_MINUTE deve ser maior que zero")
	}
	return nil
}
