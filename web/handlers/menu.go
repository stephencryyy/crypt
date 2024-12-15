// web/handlers/menu.go
package handlers

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Chat структура для чатов
type Chat struct {
	ID        int       `json:"id"`
	RoomID    string    `json:"room_id"`
	ChatName  string    `json:"chat_name"`
	CreatedAt time.Time `json:"created_at"`
}

func MenuHandler(c *gin.Context) {
	username := getCurrentUsername(c)
	if username == "" {
		// Если по какой-то причине username не сохранён в контексте
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Необходимо войти в систему"})
		return
	}

	// Получаем user_id по username
	var userID int
	err := db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username = $1", username).Scan(&userID)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		return
	}

	// Получаем чаты пользователя через chat_participants
	chatRows, err := db.QueryContext(context.Background(), `
        SELECT chats.id, chats.room_id, chats.chat_name, chats.created_at
        FROM chats
        JOIN chat_participants ON chats.id = chat_participants.chat_id
        WHERE chat_participants.user_id = $1
    `, userID)
	if err != nil {
		log.Printf("Ошибка при получении чатов: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения чатов"})
		return
	}
	defer chatRows.Close()

	var chats []Chat
	for chatRows.Next() {
		var chat Chat
		if err := chatRows.Scan(&chat.ID, &chat.RoomID, &chat.ChatName, &chat.CreatedAt); err != nil {
			log.Printf("Ошибка при чтении данных чата: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения данных чата"})
			return
		}
		chats = append(chats, chat)
	}

	// Получаем поступившие приглашения
	invitationRows, err := db.QueryContext(context.Background(), `
        SELECT i.id, i.chat_id, c.chat_name, u.username, i.created_at, i.status
        FROM invitations i
        JOIN chats c ON i.chat_id = c.id
        JOIN users u ON i.inviter_id = u.id
        WHERE i.invitee_id = $1 AND i.status = 'pending'
    `, userID)
	if err != nil {
		log.Printf("Ошибка при получении приглашений: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения приглашений"})
		return
	}
	defer invitationRows.Close()

	var invitations []Invitation
	for invitationRows.Next() {
		var inv Invitation
		var createdAt time.Time
		if err := invitationRows.Scan(&inv.ID, &inv.ChatID, &inv.ChatName, &inv.InviterUsername, &createdAt, &inv.Status); err != nil {
			log.Printf("Ошибка при чтении данных приглашения: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения данных приглашения"})
			return
		}
		inv.CreatedAt = createdAt.Format("2006-01-02 15:04:05")
		invitations = append(invitations, inv)
	}

	// Рендерим меню с чатами и приглашениями
	c.HTML(http.StatusOK, "hub.html", gin.H{
		"username":    username,
		"chats":       chats,
		"invitations": invitations,
	})
}
