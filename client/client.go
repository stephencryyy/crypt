package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	"crypt/algorithm"
	chatpb "crypt/proto/chatpb"

	"github.com/google/uuid"
)

func main() {
	// Установка соединения с сервером gRPC
	conn, err := grpc.Dial("localhost:50051",
		grpc.WithInsecure(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(1024*1024*500), // Увеличиваем максимально допустимый размер получаемого сообщения
			grpc.MaxCallSendMsgSize(1024*1024*500), // Увеличиваем максимально допустимый размер отправляемого сообщения
		),
	)

	if err != nil {
		log.Fatalf("Не удалось подключиться к серверу: %v", err)
	}
	defer conn.Close()
	exitChan := make(chan bool)

	client := chatpb.NewChatServiceClient(conn)

	// Создание комнаты или присоединение к существующей
	fmt.Print("Введите ID комнаты (или нажмите Enter для создания новой): ")
	reader := bufio.NewReader(os.Stdin)
	roomID, _ := reader.ReadString('\n')
	roomID = strings.TrimSpace(roomID)

	var algorithmName, mode, padding string
	var prime *big.Int
	if roomID == "" {
		// Создание комнаты с выбором алгоритма, режима и набивки
		fmt.Print("Выберите алгоритм (rc5): ")
		algorithmName, _ = reader.ReadString('\n')
		algorithmName = strings.TrimSpace(algorithmName)

		fmt.Print("Выберите режим шифрования (ECB, CBC, CFB, OFB, CTR, RandomDelta): ")
		mode, _ = reader.ReadString('\n')
		mode = strings.TrimSpace(mode)

		fmt.Print("Выберите режим набивки (Zeros, ANSIX923, PKCS7, ISO10126): ")
		padding, _ = reader.ReadString('\n')
		padding = strings.TrimSpace(padding)

		// Генерация общего простого числа для группы
		prime, _ = algorithm.GeneratePrime(2048)
		primeHex := hex.EncodeToString(prime.Bytes())

		// Создание комнаты
		createRoomResp, err := client.CreateRoom(context.Background(), &chatpb.CreateRoomRequest{
			Algorithm: algorithmName, // "rc5"
			Mode:      mode,
			Padding:   padding,
			Prime:     primeHex,
		})
		if err != nil {
			log.Fatalf("Ошибка при создании комнаты: %v", err)
		}
		roomID = createRoomResp.GetRoomId()
		fmt.Printf("Комната создана с ID: %s\n", roomID)
	} else {
		fmt.Printf("Присоединяемся к существующей комнате с ID: %s\n", roomID)

		// Получение параметров комнаты
		getRoomResp, err := client.GetRoom(context.Background(), &chatpb.GetRoomRequest{
			RoomId: roomID,
		})
		if err != nil {
			log.Fatalf("Ошибка при получении параметров комнаты: %v", err)
		}
		algorithmName = getRoomResp.GetAlgorithm()
		mode = getRoomResp.GetMode()
		padding = getRoomResp.GetPadding()
		primeBytes, _ := hex.DecodeString(getRoomResp.GetPrime())
		prime = new(big.Int).SetBytes(primeBytes)
	}

	// Уникальный идентификатор клиента
	clientID := uuid.New().String()

	// Присоединение к комнате
	joinResp, err := client.JoinRoom(context.Background(), &chatpb.JoinRoomRequest{
		RoomId:   roomID,
		ClientId: clientID,
	})
	if err != nil || !joinResp.GetSuccess() {
		log.Fatalf("Ошибка при присоединении к комнате: %v", err)
	}
	fmt.Println("Успешно присоединились к комнате")

	generator := big.NewInt(2)

	// Генерация ключей Диффи-Хеллмана
	privateKey, _ := algorithm.GeneratePrivateKey(prime)
	publicKey := algorithm.GeneratePublicKey(generator, privateKey, prime)
	publicKeyHex := hex.EncodeToString(publicKey.Bytes())

	// Отправка публичного ключа на сервер
	_, err = client.SendPublicKey(context.Background(), &chatpb.SendPublicKeyRequest{
		RoomId:    roomID,
		ClientId:  clientID,
		PublicKey: publicKeyHex,
	})
	if err != nil {
		log.Fatalf("Ошибка при отправке публичного ключа: %v", err)
	}

	// Переменные для инициализации cipherContext
	var cipherContextMutex sync.Mutex
	var cipherContext *algorithm.CryptoSymmetricContext

	// Мапа для хранения публичных ключей других клиентов
	otherPublicKeys := make(map[string]string)
	var sharedKeyComputed bool = false

	// Запуск горутины для получения сообщений
	go receiveMessages(client, roomID, clientID, &cipherContext,
		&cipherContextMutex, &otherPublicKeys, &sharedKeyComputed, privateKey, prime, algorithmName, mode, padding)

	go func() {
		<-exitChan
		fmt.Println("Завершаем работу программы...")
		os.Exit(0)
	}()

	// Дополнительный вызов GetPublicKeys после отправки публичного ключа
	go func() {
		for {
			if sharedKeyComputed {
				break
			}

			getKeysResp, err := client.GetPublicKeys(context.Background(), &chatpb.GetPublicKeysRequest{
				RoomId: roomID,
			})
			if err != nil {
				log.Printf("Ошибка при получении публичных ключей: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}

			for _, clientKey := range getKeysResp.GetPublicKeys() {
				if clientKey.GetClientId() != clientID && clientKey.GetPublicKey() != "" {
					otherPublicKeyHex := clientKey.GetPublicKey()
					otherPublicKeyBytes, err := hex.DecodeString(otherPublicKeyHex)
					if err != nil {
						log.Printf("Ошибка декодирования публичного ключа: %v", err)
						continue
					}
					otherPublicKey := new(big.Int).SetBytes(otherPublicKeyBytes)

					// Вычисляем общий секретный ключ
					sharedKey := algorithm.GenerateSharedKey(privateKey, otherPublicKey, prime)
					hashedSharedKey := algorithm.HashSharedKey(sharedKey)

					// Инициализируем cipherContext
					initCipher(hashedSharedKey, &cipherContext, &cipherContextMutex, algorithmName, mode, padding)
					sharedKeyComputed = true
					break
				}
			}

			if !sharedKeyComputed {
				time.Sleep(2 * time.Second)
			}
		}
	}()

	// Цикл отправки сообщений (объединённый с функционалом отправки файлов)
	for {
		fmt.Print("Введите сообщение (или 'send-file' для отправки файла): ")
		message, _ := reader.ReadString('\n')
		message = strings.TrimSpace(message)

		// Отправка файла
		if message == "send-file" {
			sendFile(client, roomID, clientID, cipherContext)
			continue
		}

		// Проверка на пустое сообщение
		if message == "" {
			continue
		}

		// Обработка команд
		if strings.HasPrefix(message, "/") {
			switch message {
			case "/close":
				// Удаление комнаты
				closeResp, err := client.CloseRoom(context.Background(), &chatpb.CloseRoomRequest{
					RoomId: roomID,
				})
				if err != nil || !closeResp.GetSuccess() {
					fmt.Printf("Ошибка при удалении комнаты: %v\n", err)
				} else {
					fmt.Println("Комната успешно удалена.")
				}
				// Завершаем работу клиента
				exitChan <- true
				return
			case "/exit":
				// Выход из комнаты
				_, err := client.LeaveRoom(context.Background(), &chatpb.LeaveRoomRequest{
					RoomId:   roomID,
					ClientId: clientID,
				})
				if err != nil {
					fmt.Printf("Ошибка при выходе из комнаты: %v\n", err)
				} else {
					fmt.Println("Вы вышли из комнаты.")
				}
				// Завершаем работу клиента
				exitChan <- true
				return
			default:
				fmt.Println("Неизвестная команда. Доступные команды: /close, /exit")
				continue
			}
		}

		// Ждем инициализации контекста шифрования
		if !sharedKeyComputed {
			fmt.Println("Контекст шифрования не инициализирован. Подождите завершения обмена ключами.")
			continue
		}

		cipherContextMutex.Lock()
		encryptedMessage, err := cipherContext.Encrypt([]byte(message))
		cipherContextMutex.Unlock()
		if err != nil {
			log.Fatalf("Ошибка при шифровании сообщения: %v", err)
		}

		// Отправляем сообщение
		_, err = client.SendMessage(context.Background(), &chatpb.SendMessageRequest{
			RoomId:           roomID,
			ClientId:         clientID,
			EncryptedMessage: encryptedMessage,
		})
		if err != nil {
			log.Fatalf("Ошибка при отправке сообщения: %v", err)
		}
		fmt.Println("Сообщение отправлено")
	}
}

func receiveMessages(
	client chatpb.ChatServiceClient,
	roomID, clientID string,
	cipherContext **algorithm.CryptoSymmetricContext,
	cipherContextMutex *sync.Mutex,
	otherPublicKeys *map[string]string,
	sharedKeyComputed *bool,
	privateKey *big.Int,
	prime *big.Int,
	algorithmName, mode, padding string,
) {
	stream, err := client.ReceiveMessages(context.Background(), &chatpb.ReceiveMessagesRequest{
		RoomId:   roomID,
		ClientId: clientID,
	})
	if err != nil {
		log.Fatalf("Ошибка при получении сообщений: %v", err)
	}

	// Maps for storing file chunks and tracking progress
	fileChunks := make(map[string][][]byte) // Map[fileKey][]byte
	fileChunkCount := make(map[string]int)  // Map[fileKey]int
	fileTotalChunks := make(map[string]int) // Map[fileKey]int
	mutex := &sync.Mutex{}                  // Mutex for thread safety

	for {
		msg, err := stream.Recv()
		if err != nil {
			log.Fatalf("Ошибка при получении сообщения из потока: %v", err)
		}

		if msg.GetType() == "public_key" {
			senderID := msg.GetSenderId()
			publicKeyHex := string(msg.GetEncryptedMessage())

			if senderID == clientID {
				// Игнорируем свои собственные публичные ключи
				continue
			}

			// Сохраняем публичный ключ другого клиента
			(*otherPublicKeys)[senderID] = publicKeyHex
			fmt.Printf("Получен публичный ключ от клиента %s\n", senderID)

			// Проверяем, получили ли мы все публичные ключи
			if len(*otherPublicKeys) >= 1 && !(*sharedKeyComputed) {
				otherPublicKeyBytes, err := hex.DecodeString(publicKeyHex)
				if err != nil {
					log.Printf("Ошибка декодирования публичного ключа: %v", err)
					continue
				}
				otherPublicKey := new(big.Int).SetBytes(otherPublicKeyBytes)

				// Вычисляем общий секретный ключ
				sharedKey := algorithm.GenerateSharedKey(privateKey, otherPublicKey, prime)
				hashedSharedKey := algorithm.HashSharedKey(sharedKey)

				fmt.Printf("Общий секретный ключ вычислен\n")

				// Инициализируем cipherContext
				initCipher(hashedSharedKey, cipherContext, cipherContextMutex, algorithmName, mode, padding)
				*sharedKeyComputed = true
			}

			continue
		}

		if msg.GetType() == "message" {
			senderID := msg.GetSenderId()
			encryptedMessage := msg.GetEncryptedMessage()

			cipherContextMutex.Lock()
			if *cipherContext == nil {
				cipherContextMutex.Unlock()
				fmt.Println("Контекст шифрования не инициализирован.")
				continue
			}
			decryptedMessage, err := (*cipherContext).Decrypt(encryptedMessage)
			cipherContextMutex.Unlock()
			if err != nil {
				fmt.Printf("Ошибка при расшифровке сообщения: %v\n", err)
				continue
			}
			fmt.Printf("Сообщение от %s: %s\n", senderID, string(decryptedMessage))
		}

		if msg.GetType() == "file" {
			senderID := msg.GetSenderId()
			encryptedChunk := msg.GetEncryptedMessage()
			fileName := msg.GetFileName()
			chunkIndex := int(msg.GetChunkIndex())
			totalChunks := int(msg.GetTotalChunks())

			fmt.Printf("Получен файл: %s от клиента %s (Chunk %d/%d)\n", fileName, senderID, chunkIndex+1, totalChunks)

			// Key to identify the file uniquely
			fileKey := senderID + "_" + fileName

			// Decrypt the chunk
			cipherContextMutex.Lock()
			if *cipherContext == nil {
				cipherContextMutex.Unlock()
				fmt.Println("Контекст шифрования не инициализирован.")
				continue
			}
			decryptedChunk, err := (*cipherContext).Decrypt(encryptedChunk)
			cipherContextMutex.Unlock()
			if err != nil {
				fmt.Printf("Ошибка при расшифровке фрагмента файла от %s: %v\n", senderID, err)
				continue
			}

			mutex.Lock()
			// Initialize data structures if first chunk
			if _, exists := fileChunks[fileKey]; !exists {
				fileChunks[fileKey] = make([][]byte, totalChunks)
				fileChunkCount[fileKey] = 0
				fileTotalChunks[fileKey] = totalChunks
			}

			// Store the chunk
			fileChunks[fileKey][chunkIndex] = decryptedChunk
			fileChunkCount[fileKey]++

			// Check if all chunks have been received
			if fileChunkCount[fileKey] == fileTotalChunks[fileKey] {
				// Reassemble the file
				var fileData []byte
				for _, chunk := range fileChunks[fileKey] {
					fileData = append(fileData, chunk...)
				}

				// Create a folder for the client if it doesn't exist
				clientFolder := filepath.Join("received_files", senderID)
				if _, err := os.Stat(clientFolder); os.IsNotExist(err) {
					err := os.MkdirAll(clientFolder, 0755)
					if err != nil {
						fmt.Printf("Ошибка при создании папки клиента: %v\n", err)
						mutex.Unlock()
						continue
					}
				}

				// Check if file already exists and modify the name if needed
				baseFileName := filepath.Base(fileName)
				outputPath := filepath.Join(clientFolder, baseFileName)

				// Check for file existence and create unique name if file exists
				ext := filepath.Ext(outputPath)
				baseName := strings.TrimSuffix(baseFileName, ext)
				counter := 1
				for {
					if _, err := os.Stat(outputPath); err == nil {
						// File exists, add counter to the filename
						outputPath = filepath.Join(clientFolder, fmt.Sprintf("%s(%d)%s", baseName, counter, ext))
						counter++
					} else {
						break
					}
				}

				fmt.Printf("Сохранение файла как: %s\n", outputPath)

				// Save the file
				err = os.WriteFile(outputPath, fileData, 0644)
				if err != nil {
					fmt.Printf("Ошибка сохранения файла: %v\n", err)
					mutex.Unlock()
					continue
				}

				fmt.Printf("Файл от %s сохранен как %s\n", senderID, outputPath)

				// Clean up
				delete(fileChunks, fileKey)
				delete(fileChunkCount, fileKey)
				delete(fileTotalChunks, fileKey)
			}
			mutex.Unlock()
		}
	}
}

func sendFile(client chatpb.ChatServiceClient, roomID, clientID string, cipherContext *algorithm.CryptoSymmetricContext) {
	fmt.Print("Введите путь к файлу для отправки: ")
	reader := bufio.NewReader(os.Stdin)
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	// Извлекаем базовое имя файла
	baseFileName := filepath.Base(filePath)

	// Чтение содержимого файла
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Ошибка чтения файла: %v\n", err)
		return
	}

	// Вывод текущего рабочего каталога
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Ошибка при получении текущего каталога:", err)
	} else {
		fmt.Println("Текущий рабочий каталог:", cwd)
	}

	// Шифруем файл
	encryptedData, err := cipherContext.Encrypt(fileData)
	if err != nil {
		fmt.Printf("Ошибка при шифровании файла: %v\n", err)
		return
	}

	// Отправляем файл
	_, err = client.SendMessage(context.Background(), &chatpb.SendMessageRequest{
		RoomId:           roomID,
		ClientId:         clientID,
		MessageType:      "file",
		FileName:         baseFileName,
		EncryptedMessage: encryptedData,
	})
	if err != nil {
		fmt.Printf("Ошибка при отправке файла: %v\n", err)
		return
	}

	fmt.Println("Файл успешно отправлен.")
}

func initCipher(hashedSharedKey []byte, cipherContext **algorithm.CryptoSymmetricContext, cipherContextMutex *sync.Mutex, algorithmName, mode, padding string) {
	// Деривация ключа и IV из hashedSharedKey
	hashedKey := sha256.Sum256(hashedSharedKey)
	finalKey := hashedKey[:16] // Используем первые 16 байт для ключа

	// Инициализируем выбранный алгоритм
	var symmetricAlgorithm algorithm.SymmetricAlgorithm
	if algorithmName == "rc5" {
		symmetricAlgorithm = algorithm.NewRC5()
	} else {
		log.Fatalf("Неизвестный алгоритм: %s", algorithmName)
	}

	// Установка ключа для выбранного алгоритма
	err := symmetricAlgorithm.SetKey(finalKey)
	if err != nil {
		log.Fatalf("Ошибка при установке ключа: %v", err)
	}

	// Преобразование режима шифрования и режима набивки
	cipherMode := algorithm.CipherMode(algorithm.CBC) // По умолчанию
	switch mode {
	case "ECB":
		cipherMode = algorithm.ECB
	case "CBC":
		cipherMode = algorithm.CBC
	case "CFB":
		cipherMode = algorithm.CFB
	case "OFB":
		cipherMode = algorithm.OFB
	case "CTR":
		cipherMode = algorithm.CTR
	case "RandomDelta":
		cipherMode = algorithm.RandomDelta
	default:
		log.Fatalf("Неизвестный режим шифрования: %s", mode)
	}

	paddingMode := algorithm.PaddingMode(algorithm.PKCS7) // По умолчанию
	switch padding {
	case "Zeros":
		paddingMode = algorithm.Zeros
	case "ANSIX923":
		paddingMode = algorithm.ANSIX923
	case "PKCS7":
		paddingMode = algorithm.PKCS7
	case "ISO10126":
		paddingMode = algorithm.ISO10126
	default:
		log.Fatalf("Неизвестный режим набивки: %s", padding)
	}

	// Деривация IV из общего секретного ключа
	ivHash := sha256.Sum256(hashedSharedKey)
	iv := ivHash[:16]

	// Инициализируем контекст шифрования
	cipherContextMutex.Lock()
	defer cipherContextMutex.Unlock()
	cipherCtx, err := algorithm.NewCryptoSymmetricContext(
		finalKey,
		symmetricAlgorithm,
		cipherMode,
		paddingMode,
		iv,
		16, // размер блока
	)
	if err != nil {
		log.Fatalf("Ошибка при инициализации контекста шифрования: %v", err)
	}
	*cipherContext = cipherCtx
}
