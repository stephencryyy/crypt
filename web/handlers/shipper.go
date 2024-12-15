// web/handlers/shipper.go

package handlers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"os"
	"sync"

	"github.com/joho/godotenv"
	"github.com/stephencryyy/crypt/algorithm"
)

// SECRET_KEY используется для шифрования приватных ключей пользователей.
// Получаем его из переменной окружения.
var secretKey []byte

func init() {
	// Загрузка переменных окружения из .env файла
	errs := godotenv.Load()
	if errs != nil {
		log.Println("Файл .env не найден, продолжаем без него")
	}
	// Получаем SECRET_KEY из переменной окружения
	keyHex := os.Getenv("SECRET_KEY")
	if keyHex == "" {
		panic("SECRET_KEY не установлена в переменных окружения")
	}
	var err error
	secretKey, err = hex.DecodeString(keyHex)
	if err != nil {
		panic("Ошибка декодирования SECRET_KEY: " + err.Error())
	}
	if len(secretKey) != 32 {
		panic("SECRET_KEY должна быть 32 байта (64 символа в hex)")
	}
}

// EncryptPrivateKey шифрует приватный ключ с использованием AES-GCM
func EncryptPrivateKey(privateKey []byte) (string, error) {
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, privateKey, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptPrivateKey дешифрует приватный ключ с использованием AES-GCM
func DecryptPrivateKey(encryptedPrivateKeyHex string) ([]byte, error) {
	encryptedPrivateKey, err := hex.DecodeString(encryptedPrivateKeyHex)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedPrivateKey) < nonceSize {
		return nil, errors.New("зашифрованный ключ слишком короткий")
	}

	nonce, ciphertext := encryptedPrivateKey[:nonceSize], encryptedPrivateKey[nonceSize:]
	privateKey, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// Глобальное хранилище для контекстов шифрования
var cipherContexts = struct {
	m map[string]*algorithm.CryptoSymmetricContext
	sync.RWMutex
}{
	m: make(map[string]*algorithm.CryptoSymmetricContext),
}

// SaveCipherContext сохраняет контекст шифрования для конкретной комнаты и пользователя
func SaveCipherContext(roomID, username string, ctx *algorithm.CryptoSymmetricContext) {
	key := roomID + "_" + username
	cipherContexts.Lock()
	defer cipherContexts.Unlock()
	cipherContexts.m[key] = ctx
}

// LoadCipherContext загружает контекст шифрования для конкретной комнаты и пользователя
func LoadCipherContext(roomID, username string) *algorithm.CryptoSymmetricContext {
	key := roomID + "_" + username
	cipherContexts.RLock()
	defer cipherContexts.RUnlock()
	return cipherContexts.m[key]
}

// InitCipher инициализирует cipherContext с заданными параметрами на основе hashedSharedKey
func InitCipher(hashedSharedKey []byte, algorithmName, mode, padding string) *algorithm.CryptoSymmetricContext {
	// Деривация ключа и IV из hashedSharedKey
	hashedKey := sha256.Sum256(hashedSharedKey)
	finalKey := hashedKey[:16] // Используем первые 16 байт для ключа

	// Инициализация выбранного алгоритма
	var symmetricAlgorithm algorithm.SymmetricAlgorithm
	switch algorithmName {
	case "rc5":
		symmetricAlgorithm = algorithm.NewRC5()
	default:
		log.Fatalf("Неизвестный алгоритм: %s", algorithmName)
	}

	// Установка ключа для выбранного алгоритма
	err := symmetricAlgorithm.SetKey(finalKey)
	if err != nil {
		log.Fatalf("Ошибка при установке ключа: %v", err)
	}

	// Преобразование режима шифрования и режима паддинга
	var cipherMode algorithm.CipherMode
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

	var paddingMode algorithm.PaddingMode
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
		log.Fatalf("Неизвестный режим паддинга: %s", padding)
	}

	// Деривация IV из общего секретного ключа
	ivHash := sha256.Sum256(hashedSharedKey)
	iv := ivHash[:16]

	// Инициализация контекста шифрования
	cipherContext, err := algorithm.NewCryptoSymmetricContext(
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

	return cipherContext
}
