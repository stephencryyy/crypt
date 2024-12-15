// handlers/files.go

package handlers

import (
	"context"
	"database/sql"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	chatpb "github.com/stephencryyy/crypt/proto/chatpb"
	"github.com/stephencryyy/crypt/web/grpcclient"
	_ "github.com/lib/pq"
)

// CipherContext интерфейс для шифрования и дешифрования
type CipherContext interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
	EncryptFileAsync(inputPath, outputPath string) <-chan error
	DecryptFileAsync(inputPath, outputPath string) <-chan error
}

const MaxUploadSize = 50 << 20 // 50 MB

// Разрешённые MIME-типы файлов
var AllowedFileTypes = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"application/pdf": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true, // DOCX
	"application/msword": true, // Для файлов .doc
	// Добавьте другие типы по необходимости
}

// FileInfo представляет информацию о файле для передачи в JSON
// handlers/files.go

// Обновленная структура FileInfo без MimeType
type FileInfo struct {
	FileName  string `json:"file_name"`
	FileSize  int64  `json:"file_size"`
	CreatedAt string `json:"created_at"`
}

// SendFileHandler обрабатывает загрузку файла с проверками
func SendFileHandler(c *gin.Context) {
	// Ограничение размера загружаемого файла
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, MaxUploadSize)

	// Получаем текущего пользователя
	usernameVal, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Необходимо авторизоваться"})
		return
	}
	username := usernameVal.(string)

	// Получаем room_id из query-параметра
	roomID := c.Query("room_id")
	if roomID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не указан room_id"})
		return
	}

	// Проверяем, что пользователь является участником комнаты
	isMember, err := IsUserInRoom(roomID, username)
	if err != nil {
		log.Printf("Ошибка проверки участника комнаты: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки доступа"})
		return
	}
	if !isMember {
		c.JSON(http.StatusForbidden, gin.H{"error": "Вы не являетесь участником этой комнаты"})
		return
	}

	// Получаем файл из формы
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		if strings.Contains(err.Error(), "http: request body too large") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Размер файла превышает допустимый предел (50 MB)."})
		} else {
			log.Printf("Ошибка получения файла: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка загрузки файла"})
		}
		return
	}
	defer file.Close()

	// Валидация типа файла
	mimeType := header.Header.Get("Content-Type")
	if !AllowedFileTypes[mimeType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неподдерживаемый тип файла"})
		return
	}

	// Экранирование имени файла для предотвращения XSS и Path Traversal
	originalFileName := filepath.Base(header.Filename)
	sanitizedFileName := sanitizeFileName(originalFileName)
	// После санитизации имени файла добавьте проверку
	if sanitizedFileName == "" || sanitizedFileName == "undefined" {
		log.Printf("Некорректное имя файла после санитизации: %s", sanitizedFileName)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректное имя файла"})
		return
	}

	// Логирование исходного и санитизированного имени файла
	log.Printf("Original File Name: %s, Sanitized File Name: %s", originalFileName, sanitizedFileName)

	// Проверка уникальности имени файла в комнате
	exists, err = DoesFileExist(roomID, sanitizedFileName)
	if err != nil {
		log.Printf("Ошибка проверки существования файла: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки файла"})
		return
	}
	if exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Файл с таким именем уже существует в этой комнате"})
		return
	}

	// Получаем cipherContext
	cipherContext := LoadCipherContext(roomID, username)
	if cipherContext == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Шифровальный контекст не найден"})
		return
	}
	// Создаём временные файлы для шифрования
	inputTempFile, err := os.CreateTemp("", "upload-*.tmp")
	if err != nil {
		log.Printf("Ошибка создания временного файла: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки файла"})
		return
	}
	defer func() {
		inputTempFile.Close()
		os.Remove(inputTempFile.Name())
	}()

	encryptedTempFile, err := os.CreateTemp("", "encrypted-*.tmp")
	if err != nil {
		log.Printf("Ошибка создания временного зашифрованного файла: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки файла"})
		return
	}
	defer func() {
		encryptedTempFile.Close()
		os.Remove(encryptedTempFile.Name())
	}()

	// Копируем загруженный файл во временный файл
	if _, err := io.Copy(inputTempFile, file); err != nil {
		log.Printf("Ошибка копирования файла во временный файл: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки файла"})
		return
	}

	// Запускаем асинхронное шифрование
	encryptErrChan := cipherContext.EncryptFileAsync(inputTempFile.Name(), encryptedTempFile.Name())

	// Ожидаем завершения шифрования
	if encryptErr := <-encryptErrChan; encryptErr != nil {
		log.Printf("Ошибка шифрования файла: %v", encryptErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка шифрования файла"})
		return
	}

	// Читаем зашифрованные данные из временного зашифрованного файла
	encryptedData, err := os.ReadFile(encryptedTempFile.Name())
	if err != nil {
		log.Printf("Ошибка чтения зашифрованного файла: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки файла"})
		return
	}

	// Сохранение файла в базу данных
	fileSize := header.Size
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = db.ExecContext(ctx,
		`INSERT INTO files (room_id, sender_id, file_name, file_size, encrypted_file, created_at) 
         VALUES ($1, $2, $3, $4, $5, $6)`,
		roomID, username, sanitizedFileName, fileSize, encryptedData, time.Now())
	if err != nil {
		log.Printf("Ошибка сохранения файла в базе данных: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сохранения файла"})
		return
	}

	// Уведомляем участников комнаты о новом файле через gRPC
	_, err = grpcclient.ChatClient.SendMessage(context.Background(), &chatpb.SendMessageRequest{
		RoomId:           roomID,
		ClientId:         username,
		EncryptedMessage: []byte{}, // Пусто, так как это файловое сообщение
		// Другие поля при необходимости
	})
	if err != nil {
		log.Printf("Ошибка отправки уведомления через gRPC: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка отправки уведомления"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Файл успешно отправлен"})
}

// ListFilesHandler обрабатывает запрос списка файлов в комнате
func ListFilesHandler(c *gin.Context) {
	roomID := c.Query("room_id")
	if roomID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не указан room_id"})
		return
	}

	// Получаем текущего пользователя
	usernameVal, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Необходимо авторизоваться"})
		return
	}
	username := usernameVal.(string)

	// Проверяем, что пользователь является участником комнаты
	isMember, err := IsUserInRoom(roomID, username)
	if err != nil {
		log.Printf("Ошибка проверки участника комнаты: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки доступа"})
		return
	}
	if !isMember {
		c.JSON(http.StatusForbidden, gin.H{"error": "Вы не являетесь участником этой комнаты"})
		return
	}

	// Получаем список файлов из базы данных
	rows, err := db.QueryContext(context.Background(), `
	SELECT file_name, file_size, created_at 
	FROM files 
	WHERE room_id = $1
	ORDER BY created_at DESC
	`, roomID)

	if err != nil {
		log.Printf("Ошибка получения файлов из базы данных: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения файлов"})
		return
	}
	defer rows.Close()

	var files []FileInfo

	for rows.Next() {
		var file FileInfo
		err := rows.Scan(&file.FileName, &file.FileSize, &file.CreatedAt)
		if err != nil {
			log.Printf("Ошибка сканирования строки файла: %v", err)
			continue
		}
		files = append(files, file)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Ошибка после сканирования строк: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки файлов"})
		return
	}

	c.JSON(http.StatusOK, files)
}

// DownloadFileHandler обрабатывает скачивание файла по имени
// DownloadFileHandler обрабатывает скачивание файла с асинхронным дешифрованием
func DownloadFileHandler(c *gin.Context) {
	roomID := c.Query("room_id")
	fileName := c.Query("file_name")
	if roomID == "" || fileName == "" {
		log.Printf("Неверные параметры: room_id=%s, file_name=%s", roomID, fileName)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Не указан room_id или file_name"})
		return
	}

	log.Printf("Запрос на скачивание файла: room_id=%s, file_name=%s", roomID, fileName)

	// Проверяем, что пользователь является участником комнаты
	usernameVal, exists := c.Get("username")
	if !exists {
		log.Printf("Пользователь не авторизован")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Необходимо авторизоваться"})
		return
	}
	username := usernameVal.(string)

	isMember, err := IsUserInRoom(roomID, username)
	if err != nil {
		log.Printf("Ошибка проверки участника комнаты: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка проверки доступа"})
		return
	}
	if !isMember {
		log.Printf("Пользователь %s не является участником комнаты %s", username, roomID)
		c.JSON(http.StatusForbidden, gin.H{"error": "Вы не являетесь участником этой комнаты"})
		return
	}

	// Получаем файл из базы данных
	var encryptedData []byte
	var sanitizedFileName string
	err = db.QueryRowContext(context.Background(), `
        SELECT encrypted_file, file_name 
        FROM files 
        WHERE room_id = $1 AND file_name = $2
    `, roomID, fileName).Scan(&encryptedData, &sanitizedFileName)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("Файл %s в комнате %s не найден", fileName, roomID)
			c.JSON(http.StatusNotFound, gin.H{"error": "Файл не найден"})
		} else {
			log.Printf("Ошибка получения файла из базы данных: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
		}
		return
	}

	log.Printf("Файл найден: %s", sanitizedFileName)

	// Получаем cipherContext
	cipherContext := LoadCipherContext(roomID, username)
	if cipherContext == nil {
		log.Printf("Шифровальный контекст не найден для пользователя %s в комнате %s", username, roomID)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Шифровальный контекст не найден"})
		return
	}

	// Создаём временные файлы для дешифрования
	encryptedTempFile, err := os.CreateTemp("", "encrypted-*.tmp")
	if err != nil {
		log.Printf("Ошибка создания временного зашифрованного файла: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки файла"})
		return
	}
	defer func() {
		encryptedTempFile.Close()
		os.Remove(encryptedTempFile.Name())
	}()

	decryptedTempFile, err := os.CreateTemp("", "decrypted-*.tmp")
	if err != nil {
		log.Printf("Ошибка создания временного дешифрованного файла: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки файла"})
		return
	}
	defer func() {
		decryptedTempFile.Close()
		os.Remove(decryptedTempFile.Name())
	}()

	// Записываем зашифрованные данные во временный файл
	if _, err := encryptedTempFile.Write(encryptedData); err != nil {
		log.Printf("Ошибка записи зашифрованных данных во временный файл: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки файла"})
		return
	}

	// Запускаем асинхронное дешифрование
	decryptErrChan := cipherContext.DecryptFileAsync(encryptedTempFile.Name(), decryptedTempFile.Name())

	// Ожидаем завершения дешифрования
	if decryptErr := <-decryptErrChan; decryptErr != nil {
		log.Printf("Ошибка дешифрования файла: %v", decryptErr)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка дешифрования файла"})
		return
	}

	// Читаем расшифрованные данные из временного файла
	decryptedData, err := os.ReadFile(decryptedTempFile.Name())
	if err != nil {
		log.Printf("Ошибка чтения расшифрованного файла: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки файла"})
		return
	}

	log.Printf("Файл %s успешно расшифрован", sanitizedFileName)

	// Определяем MIME-тип файла на основе его расширения
	mimeType := "application/octet-stream" // Значение по умолчанию
	ext := filepath.Ext(sanitizedFileName)
	if ext != "" {
		mt := mime.TypeByExtension(ext)
		if mt != "" {
			mimeType = mt
		}
	}

	// Устанавливаем заголовки для скачивания файла
	c.Header("Content-Disposition", "attachment; filename="+filepath.Base(sanitizedFileName))
	c.Header("Content-Type", mimeType)
	c.Data(http.StatusOK, mimeType, decryptedData)
}

func sanitizeFileName(fileName string) string {
	// Удаляем любые пути и оставляем только базовое имя
	fileName = filepath.Base(fileName)
	if len(fileName) > 255 {
		fileName = fileName[:255]
	}

	// Заменяем пробелы на подчеркивания
	fileName = strings.ReplaceAll(fileName, " ", "_")

	// Удаляем любые символы, кроме букв, цифр, подчеркиваний и точек
	fileName = regexp.MustCompile(`[^\w\.\-]`).ReplaceAllString(fileName, "")

	// Проверка разрешённых расширений
	allowedExtensions := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".pdf":  true,
		".docx": true, // Добавлено расширение DOCX
		".doc":  true, // Добавлено расширение DOC
		// Добавьте другие расширения по необходимости
	}

	ext := strings.ToLower(filepath.Ext(fileName))
	if !allowedExtensions[ext] {
		return "" // Возвращаем пустую строку, если расширение не разрешено
	}

	return fileName
}

// DoesFileExist проверяет, существует ли файл с таким именем в комнате
func DoesFileExist(roomID, fileName string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(context.Background(), `
        SELECT EXISTS (
            SELECT 1 
            FROM files 
            WHERE room_id = $1 AND file_name = $2
        )`, roomID, fileName).Scan(&exists)
	return exists, err
}

// IsUserInRoom проверяет, является ли пользователь участником комнаты
func IsUserInRoom(roomID, username string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(context.Background(), `
        SELECT EXISTS (
            SELECT 1 
            FROM chat_participants cp 
            JOIN users u ON cp.user_id = u.id 
            JOIN chats c ON cp.chat_id = c.id 
            WHERE c.room_id = $1 AND u.username = $2
        )`, roomID, username).Scan(&exists)
	return exists, err
}
