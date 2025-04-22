package service

import (
	"context"
	"errors"
	"time"

	"github.com/hell-ecosystem/auth-service/pkg/auth/domain"
)

type AuthService struct {
	tokenManager domain.TokenManager
	tokenStore   domain.TokenStore
	accessTTL    time.Duration
}

func NewAuthService(tm domain.TokenManager, ts domain.TokenStore, accessTTL time.Duration) *AuthService {
	return &AuthService{
		tokenManager: tm,
		tokenStore:   ts,
		accessTTL:    accessTTL,
	}
}

// Login генерирует access токен
func (a *AuthService) Login(ctx context.Context, userID, role string) (string, error) {
	return a.tokenManager.GenerateAccessToken(userID, role, a.accessTTL)
}

// Verify проверяет валидность и активность токена
func (a *AuthService) Verify(ctx context.Context, token string) (*domain.UserClaims, error) {
	claims, err := a.tokenManager.ParseAccessToken(token)
	if err != nil {
		return nil, errors.New("invalid token")
	}

	revoked, err := a.tokenStore.IsTokenRevoked(token)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, errors.New("token is revoked")
	}

	return claims, nil
}

// Revoke добавляет токен в blacklist на оставшееся время жизни
func (a *AuthService) Revoke(ctx context.Context, token string) error {
	claims, err := a.tokenManager.ParseAccessToken(token)
	if err != nil {
		return err
	}

	ttl := time.Until(claims.Expiry)
	return a.tokenStore.RevokeToken(token, int(ttl.Seconds()))
}
