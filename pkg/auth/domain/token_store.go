package domain

type TokenStore interface {
	IsTokenRevoked(token string) (bool, error)
	RevokeToken(token string, ttlSeconds int) error
}
