// web/handlers/chat.go

package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"

	"github.com/stephencryyy/cryptokurs/algorithm"
	chatpb "github.com/stephencryyy/cryptokurs/proto/chatpb"
	"github.com/stephencryyy/cryptokurs/web/grpcclient"

	"github.com/gin-gonic/gin"
)

// ChatHandler обрабатывает отображение страницы чата
// web/handlers/chat.go

func ChatHandler(c *gin.Context) {
	log.Println("A ЭТО ОБЫЧНЫЙ ВХОд")
	roomID := c.DefaultQuery("room_id", "")
	if roomID == "" {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Не указан ID комнаты"})
		return
	}

	usernameVal, exists := c.Get("username")
	if !exists {
		c.HTML(http.StatusUnauthorized, "error.html", gin.H{"error": "Необходимо авторизоваться"})
		return
	}
	username := usernameVal.(string)

	// Получаем user_id
	var userID int
	err := db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username = $1", username).Scan(&userID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Ошибка получения данных пользователя"})
		return
	}

	// Получаем chat_id
	var chatID int
	err = db.QueryRowContext(context.Background(), "SELECT id FROM chats WHERE room_id = $1", roomID).Scan(&chatID)
	if err == sql.ErrNoRows {
		c.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Чат не найден"})
		return
	} else if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Ошибка базы данных"})
		return
	}

	// Проверяем, есть ли приватный ключ у текущего пользователя для этого чата
	var encryptedPrivateKeyHex string
	err = db.QueryRowContext(context.Background(),
		"SELECT private_key FROM user_private_keys WHERE user_id = $1 AND chat_id = $2",
		userID, chatID).Scan(&encryptedPrivateKeyHex)
	if err == sql.ErrNoRows {
		c.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Приватный ключ не найден"})
		return
	} else if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Ошибка получения приватного ключа"})
		return
	}

	// Дешифруем privateKey
	privateKeyBytes, err := DecryptPrivateKey(encryptedPrivateKeyHex)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Ошибка дешифрования приватного ключа"})
		return
	}
	privateKey := new(big.Int).SetBytes(privateKeyBytes)

	// Получаем параметры чата
	getRoomResp, err := grpcclient.ChatClient.GetRoom(context.Background(), &chatpb.GetRoomRequest{RoomId: roomID})
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить параметры комнаты"})
		return
	}

	primeBytes, err := hex.DecodeString(getRoomResp.GetPrime())
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Ошибка декодирования prime"})
		return
	}
	prime := new(big.Int).SetBytes(primeBytes)

	// Проверяем количество участников в чате
	var participantCount int
	err = db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM chat_participants WHERE chat_id = $1", chatID).Scan(&participantCount)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Ошибка при проверке участников чата"})
		return
	}

	// Если в чате только один участник (текущий), значит второй ещё не принял приглашение
	if participantCount < 2 {
		c.HTML(http.StatusOK, "chat.html", gin.H{
			"room_id":  roomID,
			"messages": []chatpb.MessageRecord{},
			"error":    "Другой участник ещё не принял приглашение. Ожидаем...",
		})
		return
	}

	// Получаем публичные ключи участников
	keysResp, err := grpcclient.ChatClient.GetPublicKeys(context.Background(), &chatpb.GetPublicKeysRequest{RoomId: roomID})
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Не удалось получить публичные ключи"})
		return
	}

	var otherPublicKey *big.Int
	for _, pk := range keysResp.GetPublicKeys() {
		if pk.GetClientId() != username {
			otherPublicKeyBytes, err := hex.DecodeString(pk.GetPublicKey())
			if err != nil {
				log.Printf("Ошибка декодирования публичного ключа от %s: %v", pk.GetClientId(), err)
				continue
			}
			otherPublicKey = new(big.Int).SetBytes(otherPublicKeyBytes)
			break
		}
	}

	// Если второй участник присоединился, но публичный ключ ещё не отправил
	if otherPublicKey == nil {
		c.HTML(http.StatusOK, "chat.html", gin.H{
			"room_id":  roomID,
			"messages": []chatpb.MessageRecord{},
			"error":    "Ожидание публичного ключа другого участника",
		})
		return
	}

	// Вычисляем общий секретный ключ
	sharedKey := algorithm.GenerateSharedKey(privateKey, otherPublicKey, prime)
	hashedSharedKey := sha256.Sum256(sharedKey.Bytes())

	// Инициализируем cipherContext
	cipherContext := InitCipher(hashedSharedKey[:], getRoomResp.GetAlgorithm(), getRoomResp.GetMode(), getRoomResp.GetPadding())
	SaveCipherContext(roomID, username, cipherContext)

	// Получаем историю сообщений
	historyResp, err := grpcclient.ChatClient.GetRoomHistory(context.Background(), &chatpb.GetRoomHistoryRequest{
		RoomId: roomID,
	})
	if err != nil {
		c.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": fmt.Sprintf("Ошибка при получении истории: %v", err)})
		return
	}

	//дешифровка истории сообщений

	decryptedMessages := make([]*chatpb.MessageRecord, 0, len(historyResp.Messages))
	for _, msg := range historyResp.Messages {
		decryptedMessage, err := cipherContext.Decrypt(msg.GetEncryptedMessage())
		if err != nil {
			log.Printf("Ошибка дешифрования сообщения: %v", err)
			decryptedMessage = []byte("[не удалось расшифровать]")
		}
		decryptedMessageStr := string(decryptedMessage)
		newMsg := *msg
		newMsg.EncryptedMessage = []byte(decryptedMessageStr)
		decryptedMessages = append(decryptedMessages, &newMsg)
	}

	c.HTML(http.StatusOK, "chat.html", gin.H{
		"room_id":  roomID,
		"messages": decryptedMessages,
	})
}

// JoinChat обрабатывает присоединение пользователя к существующей комнате
func JoinChat(c *gin.Context) {
	roomID := c.PostForm("room_id")
	if roomID == "" {
		c.HTML(http.StatusBadRequest, "chat.html", gin.H{"error": "Необходимо указать ID комнаты"})
		return
	}

	usernameVal, exists := c.Get("username")
	if !exists {
		c.HTML(http.StatusUnauthorized, "chat.html", gin.H{"error": "Необходимо войти в систему"})
		return
	}
	username := usernameVal.(string)

	// Получаем user_id
	var userID int
	err := db.QueryRowContext(context.Background(), "SELECT id FROM users WHERE username = $1", username).Scan(&userID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка получения данных пользователя"})
		return
	}

	// Проверяем, что чат существует
	var chatID int
	err = db.QueryRowContext(context.Background(), "SELECT id FROM chats WHERE room_id = $1", roomID).Scan(&chatID)
	if err == sql.ErrNoRows {
		c.HTML(http.StatusNotFound, "chat.html", gin.H{"error": "Чат не найден"})
		return
	} else if err != nil {
		c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка базы данных"})
		return
	}

	// Проверяем количество участников
	var count int
	err = db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM chat_participants WHERE chat_id = $1", chatID).Scan(&count)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка проверки участников чата"})
		return
	}
	if count >= 2 {
		c.HTML(http.StatusBadRequest, "chat.html", gin.H{"error": "Чат уже заполнен"})
		return
	}

	// Добавляем участника
	_, err = db.ExecContext(context.Background(), "INSERT INTO chat_participants (chat_id, user_id) VALUES ($1, $2)", chatID, userID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка при добавлении в чат"})
		return
	}
	log.Printf("Сохранение приватного ключа для пользователя %d и чата %d", userID, chatID)
	// Проверяем, существует ли уже privateKey для пользователя в этом чате
	var existingEncryptedPrivateKeyHex string
	err = db.QueryRowContext(context.Background(),
		"SELECT private_key FROM user_private_keys WHERE user_id = $1 AND chat_id = $2",
		userID, chatID).Scan(&existingEncryptedPrivateKeyHex)
	if err == sql.ErrNoRows {
		// Генерируем новый приватный ключ
		log.Printf("Сохранение приватного ключа для пользователя %d и чата %d", userID, chatID)
		getRoomResp, err := grpcclient.ChatClient.GetRoom(context.Background(), &chatpb.GetRoomRequest{RoomId: roomID})
		if err != nil {
			c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка получения параметров чата"})
			return
		}

		primeBytes, err := hex.DecodeString(getRoomResp.GetPrime())
		if err != nil {
			c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка декодирования prime"})
			return
		}
		prime := new(big.Int).SetBytes(primeBytes)

		generator := big.NewInt(2)
		privateKey, err := algorithm.GeneratePrivateKey(prime)
		if err != nil {
			c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка генерации приватного ключа"})
			return
		}
		publicKey := algorithm.GeneratePublicKey(generator, privateKey, prime)
		publicKeyHex := hex.EncodeToString(publicKey.Bytes())

		// Шифруем приватный ключ перед сохранением с использованием EncryptPrivateKey
		encryptedPrivateKeyHex, err := EncryptPrivateKey(privateKey.Bytes())
		if err != nil {
			log.Printf("Ошибка шифрования приватного ключа: %v", err)
			c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка обработки ключа"})
			return
		}

		// Сохраняем зашифрованный приватный ключ в базе данных
		_, err = db.ExecContext(context.Background(),
			"INSERT INTO user_private_keys (user_id, chat_id, private_key) VALUES ($1, $2, $3)",
			userID, chatID, encryptedPrivateKeyHex)
		if err != nil {
			log.Printf("Ошибка сохранения privateKey: %v", err)
			c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка сохранения ключа"})
			return
		}

		// Получаем имя пользователя из контекста (из JWT или сессии)
		inviterUsernameVal, exists := c.Get("username")
		if !exists {
			c.HTML(http.StatusUnauthorized, "create_chat.html", gin.H{"error": "Необходимо войти в систему"})
			return
		}
		inviterUsername := inviterUsernameVal.(string)
		// Присоединяемся к комнате через gRPC
		joinResp, err := grpcclient.ChatClient.JoinRoom(context.Background(), &chatpb.JoinRoomRequest{
			RoomId:   roomID,
			ClientId: inviterUsername, // Используем имя пользователя в качестве идентификатора клиента
		})

		if err != nil || !joinResp.GetSuccess() {
			c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Не удалось присоединиться к комнате через gRPC"})
			return
		}

		// Отправляем публичный ключ на сервер
		_, err = grpcclient.ChatClient.SendPublicKey(context.Background(), &chatpb.SendPublicKeyRequest{
			RoomId:    roomID,
			ClientId:  username,
			PublicKey: publicKeyHex,
		})
		if err != nil {
			log.Printf("Ошибка при отправке публичного ключа: %v", err)
			c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка при отправке публичного ключа"})
			return
		}
	} else if err != nil {
		c.HTML(http.StatusInternalServerError, "chat.html", gin.H{"error": "Ошибка проверки существующего ключа"})
		return
	}

	// Перенаправляем пользователя на страницу чата
	c.Redirect(http.StatusSeeOther, "/messi/chat?room_id="+roomID)
}
