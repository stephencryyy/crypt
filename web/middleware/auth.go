// web/middleware/auth.go
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stephencryyy/crypt/web/handlers"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString, err := c.Cookie("token")
		if err != nil {
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Необходимо войти в систему"})
			c.Abort()
			return
		}

		claims := &handlers.Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return handlers.JwtKey, nil
		})

		if err != nil || !token.Valid {
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Недействительный токен"})
			c.Abort()
			return
		}

		// Сохраняем имя пользователя в контексте для использования в обработчиках
		c.Set("username", claims.Username)
		c.Next()
	}
}
