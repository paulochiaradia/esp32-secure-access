package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/paulochiaradia/esp32-secure-access/internal/auth"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"github.com/paulochiaradia/esp32-secure-access/internal/repositories"
	"gorm.io/gorm"
)

var ErrInvalidAdminCredentials = errors.New("invalid admin credentials")
var ErrAdminInactive = errors.New("admin user inactive")
var ErrInvalidRefreshToken = errors.New("invalid refresh token")
var ErrRefreshSessionRevoked = errors.New("refresh session revoked")
var ErrRefreshSessionExpired = errors.New("refresh session expired")

type AdminAuthService struct {
	DB              *gorm.DB
	AdminRepo       repositories.AdminUserRepository
	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	now             func() time.Time
}

func NewAdminAuthService(db *gorm.DB, adminRepo repositories.AdminUserRepository, jwtSecret string, accessTokenTTL time.Duration, refreshTokenTTL time.Duration) *AdminAuthService {
	return &AdminAuthService{
		DB:              db,
		AdminRepo:       adminRepo,
		JWTSecret:       jwtSecret,
		AccessTokenTTL:  accessTokenTTL,
		RefreshTokenTTL: refreshTokenTTL,
		now:             time.Now,
	}
}

func (s *AdminAuthService) Login(username, password, ip, userAgent string) (*models.AdminLoginResponse, error) {
	admin, err := s.AdminRepo.FindActiveByUsername(username)
	if err != nil {
		if errors.Is(err, repositories.ErrAdminUserNotFound) {
			if auditErr := s.createAuditLog(s.DB, nil, "admin.auth.login", "failed", "admin_user", username, ip, userAgent, map[string]any{"reason": "user_not_found"}); auditErr != nil {
				return nil, auditErr
			}
			return nil, ErrInvalidAdminCredentials
		}
		return nil, err
	}

	if !admin.Active {
		if auditErr := s.createAuditLog(s.DB, &admin.ID, "admin.auth.login", "failed", "admin_user", admin.Username, ip, userAgent, map[string]any{"reason": "inactive_user"}); auditErr != nil {
			return nil, auditErr
		}
		return nil, ErrAdminInactive
	}

	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)); err != nil {
		if auditErr := s.createAuditLog(s.DB, &admin.ID, "admin.auth.login", "failed", "admin_user", admin.Username, ip, userAgent, map[string]any{"reason": "invalid_password"}); auditErr != nil {
			return nil, auditErr
		}
		return nil, ErrInvalidAdminCredentials
	}

	now := s.now()
	accessToken, _, accessExpiresAt, err := auth.GenerateAdminToken(s.JWTSecret, fmt.Sprintf("%d", admin.ID), admin.Username, admin.Role, "access", s.AccessTokenTTL, now)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshJTI, refreshExpiresAt, err := auth.GenerateAdminToken(s.JWTSecret, fmt.Sprintf("%d", admin.ID), admin.Username, admin.Role, "refresh", s.RefreshTokenTTL, now)
	if err != nil {
		return nil, err
	}

	session := models.AdminRefreshSession{
		AdminUserID: admin.ID,
		TokenHash:   auth.HashToken(refreshToken),
		JTI:         refreshJTI,
		IssuedAt:    now,
		ExpiresAt:   refreshExpiresAt,
		IP:          ip,
		UserAgent:   userAgent,
	}
	if err := s.DB.Create(&session).Error; err != nil {
		return nil, err
	}

	if err := s.createAuditLog(s.DB, &admin.ID, "admin.auth.login", "success", "admin_user", admin.Username, ip, userAgent, nil); err != nil {
		return nil, err
	}

	return &models.AdminLoginResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		ExpiresIn:        int64(accessExpiresAt.Sub(now).Seconds()),
		RefreshToken:     refreshToken,
		RefreshExpiresIn: int64(refreshExpiresAt.Sub(now).Seconds()),
		User: models.AdminUserInfo{
			ID:       admin.ID,
			Username: admin.Username,
			Role:     admin.Role,
		},
	}, nil
}

func (s *AdminAuthService) Refresh(refreshToken, ip, userAgent string) (*models.AdminLoginResponse, error) {
	claims, err := auth.ParseAndValidateAdminToken(s.JWTSecret, refreshToken, "refresh")
	if err != nil {
		_ = s.createAuditLog(s.DB, nil, "admin.auth.refresh", "failed", "refresh_session", "", ip, userAgent, map[string]any{"reason": "invalid_token"})
		return nil, ErrInvalidRefreshToken
	}

	var response *models.AdminLoginResponse
	var failAdminUserID *uint
	var failTargetID string
	var failReason string
	var failError error
	err = s.DB.Transaction(func(tx *gorm.DB) error {
		var session models.AdminRefreshSession
		if err := tx.Where("token_hash = ?", auth.HashToken(refreshToken)).First(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				failReason = "session_not_found"
				failError = ErrInvalidRefreshToken
				return ErrInvalidRefreshToken
			}
			return err
		}

		now := s.now()
		if session.RevokedAt != nil {
			failAdminUserID = &session.AdminUserID
			failTargetID = session.JTI
			failReason = "session_revoked"
			failError = ErrRefreshSessionRevoked
			return ErrRefreshSessionRevoked
		}
		if now.After(session.ExpiresAt) {
			failAdminUserID = &session.AdminUserID
			failTargetID = session.JTI
			failReason = "session_expired"
			failError = ErrRefreshSessionExpired
			return ErrRefreshSessionExpired
		}
		if claims.Subject != fmt.Sprintf("%d", session.AdminUserID) {
			failAdminUserID = &session.AdminUserID
			failTargetID = session.JTI
			failReason = "subject_mismatch"
			failError = ErrInvalidRefreshToken
			return ErrInvalidRefreshToken
		}

		var admin models.AdminUser
		if err := tx.Where("id = ? AND active = ?", session.AdminUserID, true).First(&admin).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				failAdminUserID = &session.AdminUserID
				failTargetID = fmt.Sprintf("%d", session.AdminUserID)
				failReason = "inactive_or_missing_user"
				failError = ErrInvalidRefreshToken
				return ErrInvalidRefreshToken
			}
			return err
		}

		accessToken, _, accessExpiresAt, err := auth.GenerateAdminToken(s.JWTSecret, fmt.Sprintf("%d", admin.ID), admin.Username, admin.Role, "access", s.AccessTokenTTL, now)
		if err != nil {
			return err
		}

		newRefreshToken, newRefreshJTI, newRefreshExpiresAt, err := auth.GenerateAdminToken(s.JWTSecret, fmt.Sprintf("%d", admin.ID), admin.Username, admin.Role, "refresh", s.RefreshTokenTTL, now)
		if err != nil {
			return err
		}

		newSession := models.AdminRefreshSession{
			AdminUserID: admin.ID,
			TokenHash:   auth.HashToken(newRefreshToken),
			JTI:         newRefreshJTI,
			IssuedAt:    now,
			ExpiresAt:   newRefreshExpiresAt,
			IP:          ip,
			UserAgent:   userAgent,
		}
		if err := tx.Create(&newSession).Error; err != nil {
			return err
		}

		now = s.now()
		if err := tx.Model(&session).Updates(map[string]interface{}{
			"revoked_at":             now,
			"replaced_by_session_id": newSession.ID,
		}).Error; err != nil {
			return err
		}

		response = &models.AdminLoginResponse{
			AccessToken:      accessToken,
			TokenType:        "Bearer",
			ExpiresIn:        int64(accessExpiresAt.Sub(now).Seconds()),
			RefreshToken:     newRefreshToken,
			RefreshExpiresIn: int64(newRefreshExpiresAt.Sub(now).Seconds()),
			User: models.AdminUserInfo{
				ID:       admin.ID,
				Username: admin.Username,
				Role:     admin.Role,
			},
		}

		if err := s.createAuditLog(tx, &admin.ID, "admin.auth.refresh", "success", "refresh_session", newSession.JTI, ip, userAgent, nil); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		if failReason != "" {
			targetType := "refresh_session"
			if failReason == "inactive_or_missing_user" {
				targetType = "admin_user"
			}
			_ = s.createAuditLog(s.DB, failAdminUserID, "admin.auth.refresh", "failed", targetType, failTargetID, ip, userAgent, map[string]any{"reason": failReason})
		}
		if failError != nil {
			return nil, failError
		}
		return nil, err
	}

	return response, nil
}

func (s *AdminAuthService) createAuditLog(db *gorm.DB, adminUserID *uint, action, status, targetType, targetID, ip, userAgent string, metadata map[string]any) error {
	metadataJSON := ""
	if len(metadata) > 0 {
		payload, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		metadataJSON = string(payload)
	}

	entry := models.AdminAuditLog{
		AdminUserID:  adminUserID,
		Action:       action,
		TargetType:   targetType,
		TargetID:     targetID,
		Status:       status,
		IP:           ip,
		UserAgent:    userAgent,
		MetadataJSON: metadataJSON,
	}

	return db.Create(&entry).Error
}
