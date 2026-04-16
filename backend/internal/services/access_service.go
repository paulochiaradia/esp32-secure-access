package services

import (
	"errors"

	"github.com/paulochiaradia/esp32-secure-access/internal/auth"
	"github.com/paulochiaradia/esp32-secure-access/internal/models"
	"github.com/paulochiaradia/esp32-secure-access/internal/repositories"
)

var ErrInvalidSignature = errors.New("invalid signature")
var ErrUserNotFound = repositories.ErrUserNotFound

type AccessResult struct {
	UserName string
}

type AccessService struct {
	SecretKey string
	Repo      repositories.AccessRepository
}

func NewAccessService(secretKey string, repo repositories.AccessRepository) *AccessService {
	return &AccessService{SecretKey: secretKey, Repo: repo}
}

func (s *AccessService) ProcessAccessRequest(req models.AccessRequest) (*AccessResult, error) {
	if !auth.ValidateSignature(req.UID, req.Timestamp, req.Nonce, req.Signature, s.SecretKey) {
		if err := s.Repo.CreateAccessLog(&models.AccessLog{UID: req.UID, Status: "denied", Message: "Assinatura Inválida"}); err != nil {
			return nil, err
		}
		return nil, ErrInvalidSignature
	}

	user, err := s.Repo.FindActiveUserByUID(req.UID)
	if err != nil {
		if errors.Is(err, repositories.ErrUserNotFound) {
			if logErr := s.Repo.CreateAccessLog(&models.AccessLog{UID: req.UID, Status: "denied", Message: "UID não cadastrado"}); logErr != nil {
				return nil, logErr
			}
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	if err := s.Repo.CreateAccessLog(&models.AccessLog{UID: req.UID, Status: "authorized", Message: "Sucesso"}); err != nil {
		return nil, err
	}

	return &AccessResult{UserName: user.Name}, nil
}
