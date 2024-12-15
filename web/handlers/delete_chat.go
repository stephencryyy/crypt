// web/handlers/delete_chat.go
package handlers

import (
	"context"
	"database/sql"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// DeleteChatHandler обрабатывает удаление комнаты по room_id
func DeleteChatHandler(c *gin.Context) {
	log.Println("МЫ ЗАШЛИ В УДАЛЕНИЕ") // Получаем текущего пользователя
	usernameVal, exists := c.Get("username")
	if !exists {
		log.Println("DeleteChatHandler: Пользователь не авторизован")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Необходимо войти в систему"})
		return
	}
	username := usernameVal.(string)
	log.Println("ИМЯ ", username)

	// Получаем room_id из параметров маршрута
	roomID := c.Query("room_id") // Извлекает query-параметр

	if roomID == "" {
		log.Println("DeleteChatHandler: Не указан room_id")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не указан room_id"})
		return
	}
	log.Printf("DeleteChatHandler: Получен room_id=%s от пользователя=%s", roomID, username)

	// Получаем chat_id из базы данных по room_id
	var chatID int
	err := db.QueryRowContext(context.Background(), "SELECT id FROM chats WHERE room_id = $1", roomID).Scan(&chatID)
	if err == sql.ErrNoRows {
		log.Printf("DeleteChatHandler: Комната с room_id=%s не найдена", roomID)
		c.JSON(http.StatusNotFound, gin.H{"error": "Комната не найдена"})
		return
	} else if err != nil {
		log.Printf("DeleteChatHandler: Ошибка базы данных при получении chat_id для room_id=%s: %v", roomID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		return
	}
	log.Printf("DeleteChatHandler: Найден chat_id=%d для room_id=%s", chatID, roomID)

	// Получаем user_id текущего пользователя
	var userID int
	err = db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username = $1", username).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("DeleteChatHandler: Пользователь %s не найден", username)
			c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		} else {
			log.Printf("DeleteChatHandler: Ошибка базы данных при получении user_id для пользователя %s: %v", username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка БД"})
		}
		return
	}
	log.Printf("DeleteChatHandler: Получен user_id=%d для пользователя %s", userID, username)

	// Проверяем, является ли пользователь участником комнаты
	var existsParticipant bool
	err = db.QueryRowContext(context.Background(), "SELECT EXISTS(SELECT 1 FROM chat_participants WHERE chat_id = $1 AND user_id = $2)", chatID, userID).Scan(&existsParticipant)
	if err != nil {
		log.Printf("DeleteChatHandler: Ошибка базы данных при проверке участия пользователя %d в чате %d: %v", userID, chatID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка БД"})
		return
	}
	if !existsParticipant {
		log.Printf("DeleteChatHandler: Пользователь %d не является участником чата %d", userID, chatID)
		c.JSON(http.StatusForbidden, gin.H{"error": "У вас нет прав для удаления этой комнаты"})
		return
	}
	log.Printf("DeleteChatHandler: Пользователь %d является участником чата %d", userID, chatID)

	// Получаем список участников комнаты перед удалением
	rows, err := db.QueryContext(context.Background(), "SELECT user_id FROM chat_participants WHERE chat_id = $1", chatID)
	if err != nil {
		log.Printf("DeleteChatHandler: Ошибка получения участников комнаты %d: %v", chatID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения участников комнаты"})
		return
	}
	defer rows.Close()

	var participants []int
	for rows.Next() {
		var uid int
		if err := rows.Scan(&uid); err != nil {
			log.Printf("DeleteChatHandler: Ошибка сканирования user_id: %v", err)
			continue
		}
		participants = append(participants, uid)
	}
	log.Printf("DeleteChatHandler: Участники комнаты %d: %v", chatID, participants)

	// Удаляем комнату (все связанные записи удалятся благодаря ON DELETE CASCADE)
	_, err = db.ExecContext(context.Background(), "DELETE FROM chats WHERE id = $1", chatID)
	if err != nil {
		log.Printf("DeleteChatHandler: Ошибка удаления чата %d: %v", chatID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось удалить комнату"})
		return
	}
	log.Printf("DeleteChatHandler: Чат %d успешно удалён", chatID)

	// Получаем имена пользователей для уведомлений
	usernames := make([]string, 0, len(participants))
	for _, uid := range participants {
		var uname string
		err := db.QueryRowContext(context.Background(), "SELECT username FROM users WHERE id = $1", uid).Scan(&uname)
		if err != nil {
			log.Printf("DeleteChatHandler: Ошибка получения username для user_id %d: %v", uid, err)
			continue
		}
		usernames = append(usernames, uname)
	}
	log.Printf("DeleteChatHandler: Имена пользователей для уведомлений: %v", usernames)

	// Отправляем уведомления всем участникам о том, что чат был удалён
	for _, uname := range usernames {
		notification := map[string]interface{}{
			"type":      "chat_deleted",
			"chat_id":   chatID,
			"chat_name": "", // Можно добавить название чата до удаления, если необходимо
			"sender":    username,
		}
		err := SendNotification(uname, notification)
		if err != nil {
			log.Printf("DeleteChatHandler: Ошибка отправки уведомления пользователю %s: %v", uname, err)
		} else {
			log.Printf("DeleteChatHandler: Уведомление отправлено пользователю %s", uname)
		}
	}

	// Отправляем успешный ответ
	c.JSON(http.StatusOK, gin.H{"message": "Комната успешно удалена"})
}
