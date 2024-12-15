// web/handlers/ws.go
package handlers

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	chatpb "github.com/stephencryyy/cryptokurs/proto/chatpb"
	"google.golang.org/grpc"
)

// Объявление upgrader для WebSocket
var upgraderWS = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // В реальном приложении ограничьте происхождение
	},
}

var grpcClientWS chatpb.ChatServiceClient

func init() {
	// Устанавливаем соединение с gRPC-сервером
	conn, err := grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Не удалось подключиться к gRPC-серверу: %v", err)
	}
	grpcClientWS = chatpb.NewChatServiceClient(conn)
}

// clients хранит активные WebSocket-соединения по username
var clients = make(map[string]*websocket.Conn)
var clientsMutex sync.RWMutex

// SendNotification отправляет уведомление пользователю по его username
func SendNotification(username string, notification map[string]interface{}) error {
	clientsMutex.RLock()
	conn, exists := clients[username]
	clientsMutex.RUnlock()
	if !exists {
		log.Printf("Нет активного WebSocket-соединения для пользователя %s", username)
		return nil // Не возвращаем ошибку, если соединение не активно
	}

	// Отправляем уведомление как JSON с типом "notification"
	err := conn.WriteJSON(map[string]interface{}{
		"type":         "notification",
		"notification": notification,
	})
	if err != nil {
		log.Printf("Ошибка при отправке уведомления пользователю %s: %v", username, err)
		return err
	}

	return nil
}

// WebSocketHandler обрабатывает WebSocket соединения
func WebSocketHandler(c *gin.Context) {
	roomID := c.Query("room_id")
	username := getCurrentUsername(c)
	if username == "" {
		http.Error(c.Writer, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := upgraderWS.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println("Ошибка при обновлении соединения:", err)
		return
	}
	defer conn.Close()

	clientsMutex.Lock()
	clients[username] = conn
	clientsMutex.Unlock()
	defer func() {
		clientsMutex.Lock()
		delete(clients, username)
		clientsMutex.Unlock()
	}()

	log.Printf("Пользователь %s подключился к WebSocket\n", username)

	// Загружаем cipherContext
	cipherContext := LoadCipherContext(roomID, username)

	// Горутина для получения сообщений из gRPC
	go func() {
		stream, err := grpcClientWS.ReceiveMessages(context.Background(), &chatpb.ReceiveMessagesRequest{
			RoomId:   roomID,
			ClientId: username,
		})
		if err != nil {
			log.Println("Ошибка при подключении к ReceiveMessages:", err)
			return
		}

		for {
			msg, err := stream.Recv()
			if err != nil {
				log.Println("Ошибка при получении сообщения из gRPC потока:", err)
				return
			}

			msgType := msg.GetType()
			senderID := msg.GetSenderId()
			encrypted := msg.GetEncryptedMessage()

			var content []byte
			if cipherContext != nil && msgType == "message" { // почему только message
				// Расшифровываем сообщение
				decrypted, err := cipherContext.Decrypt(encrypted)
				if err != nil {
					log.Printf("Ошибка расшифровки сообщения от %s: %v", senderID, err)
					decrypted = []byte("[не удалось расшифровать]")
				}
				content = decrypted
			} else {
				// Если не сообщение или нет контекста - отправляем как есть
				content = encrypted
			}

			// Отправляем сообщение в WebSocket клиенту
			err = conn.WriteJSON(map[string]interface{}{
				"type":      "chat",
				"sender":    senderID,
				"content":   string(content),
				"room_id":   roomID,
				"timestamp": time.Now().Format("2006-01-02 15:04:05"),
			})
			if err != nil {
				log.Println("Ошибка при отправке сообщения в WebSocket:", err)
				return
			}
		}
	}()

	// Основной цикл чтения сообщений от клиента по WebSocket
	for {
		var msg map[string]interface{}
		err := conn.ReadJSON(&msg)
		if err != nil {
			log.Println("Ошибка при чтении сообщения:", err)
			break
		}

		msgType, ok := msg["type"].(string)
		if !ok {
			log.Println("Сообщение без типа")
			continue
		}

		switch msgType {
		case "chat":
			content, ok1 := msg["content"].(string)
			roomIDMsg, ok2 := msg["room_id"].(string)
			if !ok1 || !ok2 || content == "" || roomIDMsg == "" {
				log.Println("Некорректное содержимое сообщения")
				continue
			}

			if cipherContext == nil {
				conn.WriteJSON(map[string]interface{}{
					"type":    "error",
					"message": "Шифровальный контекст не инициализирован",
				})
				continue
			}

			encryptedMessage, err := cipherContext.Encrypt([]byte(content))
			if err != nil {
				log.Printf("Ошибка при шифровании сообщения: %v", err)
				conn.WriteJSON(map[string]interface{}{
					"type":    "error",
					"message": "Ошибка шифрования сообщения",
				})
				continue
			}

			_, err = grpcClientWS.SendMessage(context.Background(), &chatpb.SendMessageRequest{
				RoomId:           roomIDMsg,
				ClientId:         username,
				EncryptedMessage: encryptedMessage,
				MessageType:      "message",
			})
			if err != nil {
				log.Printf("Ошибка при отправке сообщения через gRPC: %v", err)
				conn.WriteJSON(map[string]interface{}{
					"type":    "error",
					"message": "Ошибка при отправке сообщения",
				})
				continue
			}

		default:
			log.Printf("Неизвестный тип сообщения: %s", msgType)
		}
	}
}
