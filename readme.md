additional service for auth

sample how to use

```go
package main

import (
    "fmt"
    "net/http"
    "time"

    "your_project/pkg/auth/infra"
    "your_project/pkg/auth/service"
    "your_project/pkg/auth/middleware"
)

func main() {
    redis := infra.NewRedisTokenStore("localhost:6379")
    jwt := infra.NewJWTManager("my-secret")
    auth := service.NewAuthService(jwt, redis, 15*time.Minute)

    mux := http.NewServeMux()
    mux.Handle("/secure", middleware.AuthMiddleware(auth)(http.HandlerFunc(secureHandler)))

    fmt.Println("Server started on :8080")
    http.ListenAndServe(":8080", mux)
}

func secureHandler(w http.ResponseWriter, r *http.Request) {
    claims, ok := middleware.GetUserClaims(r.Context())
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    fmt.Fprintf(w, "Hello %s! Your role is %s\n", claims.UserID, claims.Role)
}
```