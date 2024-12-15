// web/handlers/create_chat.go

package handlers

import (
	"context"
	"database/sql"
	"encoding/hex"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/stephencryyy/cryptokurs/algorithm" // Импорт пакета algorithm
	chatpb "github.com/stephencryyy/cryptokurs/proto/chatpb"
	"github.com/stephencryyy/cryptokurs/web/grpcclient"
)

func ShowCreateChatPage(c *gin.Context) {
	c.HTML(http.StatusOK, "create_chat.html", gin.H{})
}

// CreateChat обрабатывает создание новой комнаты чата и отправку приглашения
func CreateChat(c *gin.Context) {
	algorithmName := c.PostForm("algorithm")
	mode := c.PostForm("mode")
	padding := c.PostForm("padding")
	inviteeUsername := strings.TrimSpace(c.PostForm("invitee_username")) // Убираем пробелы

	log.Printf("Получено invitee_username: '%s'", inviteeUsername)

	// Проверяем, что invitee_username указан
	if inviteeUsername == "" {
		c.HTML(http.StatusBadRequest, "create_chat.html", gin.H{"error": "Необходимо указать имя пользователя для приглашения"})
		return
	}

	// Получаем имя пользователя из контекста (из JWT или сессии)
	inviterUsernameVal, exists := c.Get("username")
	if !exists {
		c.HTML(http.StatusUnauthorized, "create_chat.html", gin.H{"error": "Необходимо войти в систему"})
		return
	}
	inviterUsername := inviterUsernameVal.(string)

	// Получаем inviter_id из базы данных
	var inviterID int
	err := db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username = $1", inviterUsername).Scan(&inviterID)
	if err != nil {
		log.Printf("Ошибка получения inviterID: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка получения данных приглашателя"})
		return
	}

	// Получаем invitee_id из базы данных с нечувствительным к регистру поиском
	var inviteeID int
	err = db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE LOWER(username) = LOWER($1)", inviteeUsername).Scan(&inviteeID)
	if err == sql.ErrNoRows {
		c.HTML(http.StatusBadRequest, "create_chat.html", gin.H{"error": "Пользователь для приглашения не найден"})
		return
	} else if err != nil {
		log.Printf("Ошибка получения inviteeID: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка получения данных приглашенного пользователя"})
		return
	}

	// Генерация простого числа для группы
	prime, err := algorithm.GeneratePrime(2048)
	if err != nil {
		log.Printf("Ошибка генерации простого числа: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка генерации простого числа"})
		return
	}
	primeHex := hex.EncodeToString(prime.Bytes())
	log.Printf("Сгенерированное простое число (primeHex): %s", primeHex)

	// Создаем новую комнату через gRPC
	resp, err := grpcclient.ChatClient.CreateRoom(context.Background(), &chatpb.CreateRoomRequest{
		Algorithm: algorithmName,
		Mode:      mode,
		Padding:   padding,
		Prime:     primeHex,
	})

	if err != nil {
		log.Printf("Ошибка при создании комнаты через gRPC: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Не удалось создать комнату"})
		return
	}

	roomID := resp.RoomId
	log.Printf("Комната создана через gRPC с roomID: %s", roomID)

	// Вставляем новую запись в таблицу chats
	var newChatID int
	chatName := "Chat with " + inviteeUsername // Или другое значение для chat_name
	err = db.QueryRowContext(context.Background(), "INSERT INTO chats (room_id, chat_name) VALUES ($1, $2) RETURNING id", roomID, chatName).Scan(&newChatID)
	if err != nil {
		log.Printf("Ошибка вставки в таблицу chats: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка при создании чата"})
		return
	}
	log.Printf("Чат с roomID %s добавлен в базу данных с newChatID: %d", roomID, newChatID)

	// Добавляем приглашающего пользователя в chat_participants
	_, err = db.ExecContext(context.Background(), "INSERT INTO chat_participants (chat_id, user_id) VALUES ($1, $2)", newChatID, inviterID)
	if err != nil {
		log.Printf("Ошибка добавления пользователя в chat_participants: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка при добавлении пользователя в чат"})
		return
	}
	log.Printf("Пользователь с ID %d добавлен в chat_participants для чата %d", inviterID, newChatID)

	// Создаем приглашение в таблице invitations
	_, err = db.ExecContext(context.Background(), "INSERT INTO invitations (chat_id, inviter_id, invitee_id) VALUES ($1, $2, $3)", newChatID, inviterID, inviteeID)
	if err != nil {
		log.Printf("Ошибка создания приглашения: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка при создании приглашения"})
		return
	}
	log.Printf("Приглашение создано для пользователя с ID %d в чат %d", inviteeID, newChatID)

	// Генерируем ключи Диффи-Хеллмана для инициатора
	generator := big.NewInt(2)
	privateKey, err := algorithm.GeneratePrivateKey(prime)
	if err != nil {
		log.Printf("Ошибка генерации приватного ключа: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка генерации ключа"})
		return
	}
	publicKey := algorithm.GeneratePublicKey(generator, privateKey, prime)
	publicKeyHex := hex.EncodeToString(publicKey.Bytes())

	// Шифруем приватный ключ перед сохранением
	encryptedPrivateKeyHex, err := EncryptPrivateKey(privateKey.Bytes())
	if err != nil {
		log.Printf("Ошибка шифрования приватного ключа: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка обработки ключа"})
		return
	}

	// Сохраняем зашифрованный приватный ключ в базе данных
	_, err = db.ExecContext(context.Background(),
		"INSERT INTO user_private_keys (user_id, chat_id, private_key) VALUES ($1, $2, $3)",
		inviterID, newChatID, encryptedPrivateKeyHex)
	if err != nil {
		log.Printf("Ошибка сохранения privateKey: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка сохранения ключа"})
		return
	}

	// Присоединяемся к комнате через gRPC
	joinResp, err := grpcclient.ChatClient.JoinRoom(context.Background(), &chatpb.JoinRoomRequest{
		RoomId:   roomID,
		ClientId: inviterUsername,
	})
	if err != nil || !joinResp.Success {
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Не удалось присоединиться к комнате после её создания"})
		return
	}
	log.Println("Успешно присоединились к комнате через gRPC")

	// Отправляем публичный ключ на сервер
	_, err = grpcclient.ChatClient.SendPublicKey(context.Background(), &chatpb.SendPublicKeyRequest{
		RoomId:    roomID,
		ClientId:  inviterUsername,
		PublicKey: publicKeyHex,
	})
	if err != nil {
		log.Printf("Ошибка при отправке публичного ключа: %v", err)
		c.HTML(http.StatusInternalServerError, "create_chat.html", gin.H{"error": "Ошибка при отправке публичного ключа"})
		return
	}
	log.Println("Публичный ключ отправлен на сервер")

	// Отправляем уведомление приглашенному пользователю через WebSocket
	notification := map[string]interface{}{
		"type":      "invitation_sent",
		"chat_id":   newChatID,
		"chat_name": chatName,
		"sender":    inviterUsername,
	}
	err = SendNotification(inviteeUsername, notification)
	if err != nil {
		log.Printf("Error sending WebSocket notification to %s: %v", inviteeUsername, err)
		// Не обязательно возвращать ошибку, если уведомление не отправлено
	}

	// Перенаправление на страницу меню чатов
	c.Redirect(http.StatusSeeOther, "/messi/hub")
}
