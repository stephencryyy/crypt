package handlers

import (
	"context"
	"database/sql"
	"encoding/hex"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	// Импорт пакета algorithm
	"github.com/stephencryyy/crypt/algorithm"
	chatpb "github.com/stephencryyy/crypt/proto/chatpb"
	"github.com/stephencryyy/crypt/web/grpcclient"

	"github.com/gin-gonic/gin"
)

// Invitation структура для данных из таблицы invitations
type Invitation struct {
	ID              int    `json:"id"`
	ChatID          int    `json:"chat_id"`
	ChatName        string `json:"chat_name"`
	Sender          string `json:"sender"`
	Receiver        string `json:"receiver"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	InviterUsername string `json:"inviter_username"`
}

// SendInvitationHandler отправляет приглашение в комнату
func SendInvitationHandler(c *gin.Context) {
	// Получаем текущего пользователя (sender)
	sender := getCurrentUsername(c)
	if sender == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Необходимо войти в систему"})
		return
	}

	// Получаем receiver из формы
	receiver := strings.TrimSpace(c.PostForm("receiver"))
	chatIDStr := c.PostForm("chat_id")

	// Проверяем, не пытается ли пользователь пригласить самого себя
	if sender == receiver {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Нельзя отправлять приглашение самому себе"})
		return
	}

	// Проверяем, существует ли пользователь-получатель
	var userExists bool
	err := db.QueryRowContext(context.Background(), "SELECT EXISTS(SELECT 1 FROM users WHERE username=$1)", receiver).Scan(&userExists)
	if err != nil {
		log.Printf("Database error while checking user existence: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка БД"})
		return
	}
	if !userExists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}

	// Получаем ID отправителя
	var senderID int
	err = db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username=$1", sender).Scan(&senderID)
	if err != nil {
		log.Printf("Database error while fetching sender ID: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка БД"})
		return
	}

	// Получаем ID чата из chat_id
	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID чата"})
		return
	}

	// Проверяем, что чат существует и пользователь уже в нём состоит
	var exists bool
	err = db.QueryRowContext(context.Background(), `
		SELECT EXISTS(
			SELECT 1 FROM chat_participants 
			WHERE chat_id = $1 AND user_id = $2
		)
	`, chatID, senderID).Scan(&exists)
	if err != nil {
		log.Printf("Database error while checking chat participation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка БД"})
		return
	}
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Вы не состоите в данном чате"})
		return
	}

	// Получаем ID получателя
	var receiverID int
	err = db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username=$1", receiver).Scan(&receiverID)
	if err != nil {
		log.Printf("Error fetching receiver ID: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения ID получателя"})
		return
	}

	// Проверяем, не существует ли уже приглашение для той же комнаты и получателя
	var existsInv bool
	err = db.QueryRowContext(context.Background(),
		"SELECT EXISTS(SELECT 1 FROM invitations WHERE chat_id=$1 AND inviter_id=$2 AND invitee_id=$3 AND status='pending')",
		chatID, senderID, receiverID).Scan(&existsInv)
	if err != nil {
		log.Printf("Database error while checking existing invitations: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка БД"})
		return
	}
	if existsInv {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Приглашение уже отправлено этому пользователю для данной комнаты"})
		return
	}

	// Вставляем приглашение в БД
	_, err = db.ExecContext(context.Background(),
		"INSERT INTO invitations (chat_id, inviter_id, invitee_id) VALUES ($1, $2, $3)",
		chatID, senderID, receiverID)
	if err != nil {
		log.Printf("Database error while inserting invitation: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось создать приглашение"})
		return
	}

	// Отправить уведомление через WebSocket уведомлений (если реализовано)
	notification := map[string]interface{}{
		"type":      "invitation_sent",
		"chat_id":   chatID,
		"chat_name": getChatName(chatID),
		"sender":    sender,
	}
	err = SendNotification(receiver, notification)
	if err != nil {
		log.Printf("Error sending WebSocket notification to %s: %v", receiver, err)
		// Не обязательно возвращать ошибку, если уведомление не отправлено
	}

	c.JSON(http.StatusOK, gin.H{"message": "Приглашение отправлено"})
}

// getChatName возвращает название чата по его ID
func getChatName(chatID int) string {
	var chatName string
	err := db.QueryRowContext(context.Background(), "SELECT chat_name FROM chats WHERE id=$1", chatID).Scan(&chatName)
	if err != nil {
		log.Printf("Error fetching chat name for chat ID %d: %v", chatID, err)
		return "Неизвестный чат"
	}
	return chatName
}

// ListInvitationsHandler возвращает список приглашений для текущего пользователя
func ListInvitationsHandler(c *gin.Context) {
	receiver := getCurrentUsername(c)
	if receiver == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Необходимо войти в систему"})
		return
	}

	// Получаем user_id получателя
	var receiverID int
	err := db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username = $1", receiver).Scan(&receiverID)
	if err != nil {
		log.Printf("Ошибка при получении ID пользователя: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		return
	}

	// Выполняем JOIN с таблицей chats и users для получения названия комнаты и отправителя
	query := `
		SELECT i.id, i.chat_id, c.chat_name, u.username, i.created_at
		FROM invitations i
		JOIN chats c ON i.chat_id = c.id
		JOIN users u ON i.inviter_id = u.id
		WHERE i.invitee_id = $1 AND i.status = 'pending'
	`
	rows, err := db.QueryContext(context.Background(), query, receiverID)
	if err != nil {
		log.Printf("Ошибка при выполнении запроса приглашений: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		return
	}
	defer rows.Close()

	var invitations []Invitation
	for rows.Next() {
		var inv Invitation
		var createdAt time.Time
		if err := rows.Scan(&inv.ID, &inv.ChatID, &inv.ChatName, &inv.InviterUsername, &createdAt); err != nil {
			log.Printf("Ошибка при сканировании приглашения: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения данных приглашения"})
			return
		}
		inv.CreatedAt = createdAt.Format("2006-01-02 15:04:05")
		invitations = append(invitations, inv)
	}

	c.JSON(http.StatusOK, gin.H{"invitations": invitations})
}

// RespondInvitationHandler обрабатывает принятие или отклонение приглашения
// RespondInvitationHandler обрабатывает принятие или отклонение приглашения
func RespondInvitationHandler(c *gin.Context) {
	invitationIDStr := c.PostForm("id")
	action := strings.ToLower(c.PostForm("action")) // "accepted" или "declined"

	// Преобразуем invitation_id из строки в int
	invitationID, err := strconv.Atoi(invitationIDStr)
	if err != nil {
		log.Printf("Invalid invitation ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный ID приглашения"})
		return
	}

	receiver := getCurrentUsername(c)
	if receiver == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Необходимо войти в систему"})
		return
	}

	// Получаем user_id из базы данных
	var userID int
	err = db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username = $1", receiver).Scan(&userID)
	if err != nil {
		log.Printf("Error fetching user ID: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения данных пользователя"})
		return
	}

	// Получаем информацию о приглашении
	var chatID int
	var senderID int
	var status string
	err = db.QueryRowContext(context.Background(), "SELECT chat_id, inviter_id, status FROM invitations WHERE id = $1 AND invitee_id = $2", invitationID, userID).Scan(&chatID, &senderID, &status)
	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, gin.H{"error": "Приглашение не найдено"})
		return
	} else if err != nil {
		log.Printf("Error fetching invitation: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения данных приглашения"})
		return
	}

	// Проверяем статус приглашения
	if status != "pending" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Приглашение уже обработано"})
		return
	}

	// Получаем chat_name из chat_id
	var chatName string
	err = db.QueryRowContext(context.Background(), "SELECT chat_name FROM chats WHERE id = $1", chatID).Scan(&chatName)
	if err != nil {
		log.Printf("Error fetching chat name: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения имени чата"})
		return
	}

	if action == "accepted" {
		// Обновляем статус приглашения на 'accepted'
		_, err := db.ExecContext(context.Background(), "UPDATE invitations SET status='accepted' WHERE id=$1", invitationID)
		if err != nil {
			log.Printf("Database error while updating invitation status: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления статуса приглашения"})
			return
		}

		// Добавляем приглашенного пользователя в chat_participants
		_, err = db.ExecContext(context.Background(), "INSERT INTO chat_participants (chat_id, user_id) VALUES ($1, $2)", chatID, userID)
		if err != nil {
			log.Printf("Error adding user to chat: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка добавления пользователя в чат"})
			return
		}

		// Получаем inviterUsername
		var inviterUsername string
		err = db.QueryRowContext(context.Background(), "SELECT username FROM users WHERE id = $1", senderID).Scan(&inviterUsername)
		if err != nil {
			log.Printf("Error fetching inviter username: %v", err)
			// Не критично, продолжаем
		} else {
			notification := map[string]interface{}{
				"type":      "invitation_accepted",
				"chat_id":   chatID,
				"chat_name": chatName,
				"sender":    receiver,
			}
			err = SendNotification(inviterUsername, notification)
			if err != nil {
				log.Printf("Error sending WebSocket notification to %s: %v", inviterUsername, err)
			}
		}

		// Получаем room_id для чата
		var roomID string
		err = db.QueryRowContext(context.Background(), "SELECT room_id FROM chats WHERE id = $1", chatID).Scan(&roomID)
		if err != nil {
			log.Printf("Error fetching room_id for chat_id %d: %v", chatID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения данных чата"})
			return
		}

		// ВАЖНО: Сначала вызываем JoinRoom для второго участника
		joinResp, err := grpcclient.ChatClient.JoinRoom(context.Background(), &chatpb.JoinRoomRequest{
			RoomId:   roomID,
			ClientId: receiver, // Используем имя второго пользователя как ClientId
		})
		if err != nil || !joinResp.GetSuccess() {
			log.Printf("Не удалось присоединить второго участника (receiver=%s) к комнате gRPC: %v", receiver, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось присоединиться к комнате через gRPC"})
			return
		}

		// --- Генерация ключей для присоединившегося пользователя ---
		getRoomResp, err := grpcclient.ChatClient.GetRoom(context.Background(), &chatpb.GetRoomRequest{RoomId: roomID})
		if err != nil {
			log.Printf("Ошибка получения параметров комнаты: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения параметров комнаты"})
			return
		}

		primeBytes, err := hex.DecodeString(getRoomResp.GetPrime())
		if err != nil {
			log.Printf("Ошибка декодирования prime: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка декодирования prime"})
			return
		}
		prime := new(big.Int).SetBytes(primeBytes)
		generator := big.NewInt(2)

		privateKey, err := algorithm.GeneratePrivateKey(prime)
		if err != nil {
			log.Printf("Ошибка генерации приватного ключа: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка генерации приватного ключа"})
			return
		}
		publicKey := algorithm.GeneratePublicKey(generator, privateKey, prime)
		publicKeyHex := hex.EncodeToString(publicKey.Bytes())

		// Шифруем приватный ключ перед сохранением
		encryptedPrivateKeyHex, err := EncryptPrivateKey(privateKey.Bytes())
		if err != nil {
			log.Printf("Ошибка шифрования приватного ключа: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка шифрования ключа"})
			return
		}

		// Сохраняем приватный ключ в БД
		_, err = db.ExecContext(context.Background(),
			"INSERT INTO user_private_keys (user_id, chat_id, private_key) VALUES ($1, $2, $3)",
			userID, chatID, encryptedPrivateKeyHex)
		if err != nil {
			log.Printf("Ошибка сохранения приватного ключа: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения приватного ключа"})
			return
		}

		// Отправляем публичный ключ на сервер gRPC
		_, err = grpcclient.ChatClient.SendPublicKey(context.Background(), &chatpb.SendPublicKeyRequest{
			RoomId:    roomID,
			ClientId:  receiver, // Используем имя присоединившегося пользователя
			PublicKey: publicKeyHex,
		})
		if err != nil {
			log.Printf("Ошибка при отправке публичного ключа: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при отправке публичного ключа"})
			return
		}
		// --- Конец генерации ключей ---

		redirectURL := "/messi/chat?room_id=" + roomID
		c.JSON(http.StatusOK, gin.H{"message": "Приглашение принято, вы присоединились к комнате", "redirect_url": redirectURL})

	} else if action == "declined" {
		// Обновляем статус приглашения на 'declined'
		_, err := db.ExecContext(context.Background(), "UPDATE invitations SET status='declined' WHERE id=$1", invitationID)
		if err != nil {
			log.Printf("Database error while updating invitation status: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обновления статуса приглашения"})
			return
		}

		var inviterUsername string
		err = db.QueryRowContext(context.Background(), "SELECT username FROM users WHERE id = $1", senderID).Scan(&inviterUsername)
		if err != nil {
			log.Printf("Error fetching inviter username: %v", err)
		} else {
			notification := map[string]interface{}{
				"type":      "invitation_declined",
				"chat_id":   chatID,
				"chat_name": chatName,
				"sender":    receiver,
			}
			err = SendNotification(inviterUsername, notification)
			if err != nil {
				log.Printf("Error sending WebSocket notification to %s: %v", inviterUsername, err)
			}
		}

		c.JSON(http.StatusOK, gin.H{"message": "Приглашение отклонено", "redirect_url": "/messi/hub"})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректное действие"})
	}
}

// getCurrentUsername извлекает имя пользователя из контекста.
func getCurrentUsername(c *gin.Context) string {
	username, exists := c.Get("username")
	if !exists {
		return ""
	}

	// Проверяем тип для безопасности
	if usernameStr, ok := username.(string); ok {
		return usernameStr
	}

	return ""
}
