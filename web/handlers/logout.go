// web/handlers/logout.go
package handlers

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// LogoutHandler отвечает за выход пользователя из системы путем удаления JWT-токена из cookie.
func LogoutHandler(c *gin.Context) {
	log.Println("LogoutHandler: User is logging out")

	// Создаём объект cookie с теми же параметрами, что и при установке, но с пустым значением и истёкшим временем
	cookie := &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		Domain:   "",                   // Оставляем пустым для текущего домена
		Expires:  time.Unix(0, 0),      // Устанавливаем время истечения в прошлое
		MaxAge:   -1,                   // Устанавливаем отрицательное значение для удаления
		Secure:   false,                // Установите true, если используете HTTPS
		HttpOnly: true,                 // Чтобы предотвратить доступ из JavaScript
		SameSite: http.SameSiteLaxMode, // Добавляем для совместимости
	}

	// Устанавливаем cookie в заголовках ответа
	http.SetCookie(c.Writer, cookie)

	// Перенаправляем пользователя на страницу входа
	c.Redirect(http.StatusSeeOther, "/login")
}
