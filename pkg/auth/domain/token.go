package domain

import "time"

type TokenManager interface {
	GenerateAccessToken(userID, role string, ttl time.Duration) (string, error)
	ParseAccessToken(token string) (*UserClaims, error)
}
