package infra

import (
	"context"
	"time"

	"github.com/hell-ecosystem/auth-service/pkg/auth/domain"

	"github.com/redis/go-redis/v9"
)

type redisStore struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisTokenStore(addr string) domain.TokenStore {
	rdb := redis.NewClient(&redis.Options{
		Addr: addr,
	})

	return &redisStore{
		client: rdb,
		ctx:    context.Background(),
	}
}

func (r *redisStore) IsTokenRevoked(token string) (bool, error) {
	exists, err := r.client.Exists(r.ctx, "blacklist:"+token).Result()
	return exists == 1, err
}

func (r *redisStore) RevokeToken(token string, ttlSeconds int) error {
	return r.client.Set(r.ctx, "blacklist:"+token, "revoked", time.Duration(ttlSeconds)*time.Second).Err()
}
