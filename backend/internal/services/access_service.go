package services

import (
	"errors"
	"time"

	"github.com/paulochiaradia/esp32-secure-access/internal/auth"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"github.com/paulochiaradia/esp32-secure-access/internal/repositories"
)

var ErrInvalidSignature = errors.New("invalid signature")
var ErrUserNotFound = repositories.ErrUserNotFound
var ErrReplayDetected = errors.New("replay attack detected")
var ErrInvalidTimestamp = errors.New("invalid timestamp")

type AccessResult struct {
	UserName string
}

type AccessService struct {
	SecretKey        string
	UserRepo         repositories.UserRepository
	AccessLogRepo    repositories.AccessLogRepository
	NonceRepo        repositories.NonceRepository
	AllowedClockSkew time.Duration
	NonceTTL         time.Duration
	now              func() time.Time
}

func NewAccessService(
	secretKey string,
	userRepo repositories.UserRepository,
	accessLogRepo repositories.AccessLogRepository,
	nonceRepo repositories.NonceRepository,
	allowedClockSkew time.Duration,
	nonceTTL time.Duration,
) *AccessService {
	return &AccessService{
		SecretKey:        secretKey,
		UserRepo:         userRepo,
		AccessLogRepo:    accessLogRepo,
		NonceRepo:        nonceRepo,
		AllowedClockSkew: allowedClockSkew,
		NonceTTL:         nonceTTL,
		now:              time.Now,
	}
}

func (s *AccessService) ProcessAccessRequest(req models.AccessRequest) (*AccessResult, error) {
	now := s.now()
	if err := s.NonceRepo.DeleteExpired(now); err != nil {
		return nil, err
	}

	reqTime := time.Unix(req.Timestamp, 0)
	if reqTime.Before(now.Add(-s.AllowedClockSkew)) || reqTime.After(now.Add(s.AllowedClockSkew)) {
		if err := s.AccessLogRepo.CreateAccessLog(&models.AccessLog{UID: req.UID, Status: "denied", Message: "Timestamp inválido ou expirado"}); err != nil {
			return nil, err
		}
		return nil, ErrInvalidTimestamp
	}

	if !auth.ValidateSignature(req.UID, req.Timestamp, req.Nonce, req.Signature, s.SecretKey) {
		if err := s.AccessLogRepo.CreateAccessLog(&models.AccessLog{UID: req.UID, Status: "denied", Message: "Assinatura Inválida"}); err != nil {
			return nil, err
		}
		return nil, ErrInvalidSignature
	}

	used, err := s.NonceRepo.Exists(req.UID, req.Nonce)
	if err != nil {
		return nil, err
	}
	if used {
		if err := s.AccessLogRepo.CreateAccessLog(&models.AccessLog{UID: req.UID, Status: "denied", Message: "Replay detectado"}); err != nil {
			return nil, err
		}
		return nil, ErrReplayDetected
	}

	if err := s.NonceRepo.Save(&models.UsedNonce{UID: req.UID, Nonce: req.Nonce, ExpiresAt: now.Add(s.NonceTTL)}); err != nil {
		return nil, err
	}

	user, err := s.UserRepo.FindActiveUserByUID(req.UID)
	if err != nil {
		if errors.Is(err, repositories.ErrUserNotFound) {
			if logErr := s.AccessLogRepo.CreateAccessLog(&models.AccessLog{UID: req.UID, Status: "denied", Message: "UID não cadastrado"}); logErr != nil {
				return nil, logErr
			}
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if err := s.AccessLogRepo.CreateAccessLog(&models.AccessLog{UID: req.UID, Status: "authorized", Message: "Sucesso"}); err != nil {
		return nil, err
	}

	return &AccessResult{UserName: user.Name}, nil
}
