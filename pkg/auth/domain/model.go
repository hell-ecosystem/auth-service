package domain

import "time"

type UserClaims struct {
	UserID string
	Role   string
	Expiry time.Time
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}
