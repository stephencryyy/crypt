// web/handlers/auth.go
package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	_ "github.com/jackc/pgx/v5/stdlib" // импортируем драйвер pgx
	"golang.org/x/crypto/bcrypt"
)

var JwtKey = []byte("your_secret_key") // замените на надежный ключ

type Credentials struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

var db *sql.DB // Глобальное подключение к БД

func InitializeDB(dataSourceName string) error {
	var err error
	db, err = sql.Open("pgx", dataSourceName)
	if err != nil {
		return fmt.Errorf("failed to open DB: %w", err)
	}

	// Проверяем подключение
	if err := db.Ping(); err != nil {
		return fmt.Errorf("failed to ping DB: %w", err)
	}
	return nil
}

func Register(c *gin.Context) {
	var creds Credentials
	if err := c.ShouldBind(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var exists bool
	err := db.QueryRowContext(context.Background(), "SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", creds.Username).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	if exists {
		c.Redirect(http.StatusSeeOther, "/register?success=0")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not hash password"})
		return
	}

	_, err = db.ExecContext(context.Background(), "INSERT INTO users (username, password) VALUES ($1, $2)", creds.Username, hashedPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save user"})
		return
	}

	c.Set("success", "Регистрация прошла успешно. Теперь вы можете войти.")
	c.Redirect(http.StatusSeeOther, "/login?success=1")
}

func Login(c *gin.Context) {
	var creds Credentials
	if err := c.ShouldBind(&creds); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var storedPassword string
	err := db.QueryRowContext(context.Background(), "SELECT password FROM users WHERE username=$1", creds.Username).Scan(&storedPassword)
	if err == sql.ErrNoRows {
		c.Redirect(http.StatusSeeOther, "/login?error=username_or_password_incorrect")
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password)); err != nil {
		c.Redirect(http.StatusSeeOther, "/login?error=username_or_password_incorrect")
		return
	}

	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: creds.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
		return
	}

	// Создаём объект cookie с дополнительными параметрами
	cookie := &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		Domain:   "", // Оставляем пустым для текущего домена
		Expires:  expirationTime,
		MaxAge:   int(expirationTime.Sub(time.Now()).Seconds()),
		Secure:   false,                // Установите true, если используете HTTPS
		HttpOnly: true,                 // Чтобы предотвратить доступ из JavaScript
		SameSite: http.SameSiteLaxMode, // Добавляем для совместимости
	}

	// Устанавливаем cookie в заголовках ответа
	http.SetCookie(c.Writer, cookie)

	c.Redirect(http.StatusSeeOther, "/messi/hub")
}
