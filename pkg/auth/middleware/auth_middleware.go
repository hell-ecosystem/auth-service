package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/hell-ecosystem/auth-service/pkg/auth/domain"
	"github.com/hell-ecosystem/auth-service/pkg/auth/service"
)

type contextKey string

const userClaimsKey contextKey = "userClaims"

func AuthMiddleware(auth *service.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := auth.Verify(r.Context(), token)
			if err != nil {
				http.Error(w, "Invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), userClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserClaims извлекает claims из контекста
func GetUserClaims(ctx context.Context) (*domain.UserClaims, bool) {
	claims, ok := ctx.Value(userClaimsKey).(*domain.UserClaims)
	return claims, ok
}
