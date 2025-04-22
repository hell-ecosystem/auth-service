package infra

import (
	"time"

	"github.com/hell-ecosystem/auth-service/pkg/auth/domain"

	"github.com/golang-jwt/jwt/v5"
)

type jwtManager struct {
	secret []byte
}

type customClaims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func NewJWTManager(secret string) domain.TokenManager {
	return &jwtManager{secret: []byte(secret)}
}

func (j *jwtManager) GenerateAccessToken(userID, role string, ttl time.Duration) (string, error) {
	claims := customClaims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

func (j *jwtManager) ParseAccessToken(tokenStr string) (*domain.UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &customClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.secret, nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}

	claims, ok := token.Claims.(*customClaims)
	if !ok {
		return nil, err
	}

	return &domain.UserClaims{
		UserID: claims.UserID,
		Role:   claims.Role,
		Expiry: claims.ExpiresAt.Time,
	}, nil
}
