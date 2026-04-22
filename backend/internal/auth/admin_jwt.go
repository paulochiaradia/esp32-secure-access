package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const adminTokenIssuer = "esp32-secure-access-admin"

// AdminClaims representa os claims usados pelos tokens administrativos.
type AdminClaims struct {
	Username  string `json:"username"`
	Role      string `json:"role"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

// GenerateAdminToken cria um JWT assinado para sessao administrativa.
func GenerateAdminToken(secret string, subject string, username string, role string, tokenType string, ttl time.Duration, now time.Time) (tokenString string, jti string, expiresAt time.Time, err error) {
	jti, err = randomTokenID()
	if err != nil {
		return "", "", time.Time{}, err
	}

	expiresAt = now.Add(ttl)
	claims := AdminClaims{
		Username:  username,
		Role:      role,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    adminTokenIssuer,
			Subject:   subject,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString([]byte(secret))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("falha ao assinar token: %w", err)
	}

	return tokenString, jti, expiresAt, nil
}

// HashToken produz um hash deterministico do token para armazenamento seguro.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ParseAndValidateAdminToken valida assinatura, issuer e tipo do token administrativo.
func ParseAndValidateAdminToken(secret string, tokenString string, expectedTokenType string) (*AdminClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AdminClaims{}, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("algoritmo inesperado: %s", token.Method.Alg())
		}
		return []byte(secret), nil
	}, jwt.WithIssuer(adminTokenIssuer))
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*AdminClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("token administrativo invalido")
	}
	if claims.TokenType != expectedTokenType {
		return nil, fmt.Errorf("tipo de token inesperado")
	}

	return claims, nil
}

func randomTokenID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("falha ao gerar identificador de token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
