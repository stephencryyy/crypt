package algorithm

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Интерфейс для расширения ключа (п.1)
type KeyRound interface {
	GenerateKeys(inputKey []byte) ([][]byte, error)
}

// Интерфейс для шифрующего преобразования (п.2)
type CipherTransform interface {
	Encryption(inputBlock, roundKey []byte) ([]byte, error)
	Decryption(inputBlock, roundKey []byte) ([]byte, error)
}

// Интерфейс для симметричного алгоритма (п.3)
type SymmetricAlgorithm interface {
	SetKey(key []byte) error
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

// Режимы шифрования
type CipherMode int

const (
	ECB = iota
	CBC
	PCBC
	CFB
	OFB
	CTR
	RandomDelta
)

// Режимы набивки
type PaddingMode int

const (
	Zeros = iota
	ANSIX923
	PKCS7
	ISO10126
)

// Класс, репрезентирующий контекст выполнения симметричного криптографического алгоритма (п.4)
type CryptoSymmetricContext struct {
	key         []byte
	cipher      SymmetricAlgorithm
	mode        CipherMode
	padding     PaddingMode
	iv          []byte
	extraParams map[string]interface{}
	blockSize   int
}

// конструктор
func NewCryptoSymmetricContext(
	key []byte,
	cipher SymmetricAlgorithm,
	mode CipherMode,
	padding PaddingMode,
	iv []byte,
	blockSize int,
	extraParams ...interface{}) (*CryptoSymmetricContext, error) {

	// Проверка длины ключа
	if len(key) != blockSize && len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key size is invalid")
	}

	// Инициализация контекста
	cstc := &CryptoSymmetricContext{
		key:         key,
		cipher:      cipher,
		mode:        mode,
		padding:     padding,
		iv:          iv,
		extraParams: make(map[string]interface{}),
		blockSize:   blockSize,
	}
	//fmt.Printf("IV установлен в контексте: %x\n", iv)

	// Установка ключа в cipher
	if err := cstc.cipher.SetKey(key); err != nil {
		return nil, fmt.Errorf("failed to set key: %w", err)
	}

	// Обработка дополнительных параметров
	for i := 0; i < len(extraParams); i += 2 {
		if i+1 < len(extraParams) {
			paramKey, ok := extraParams[i].(string)
			if ok {
				cstc.extraParams[paramKey] = extraParams[i+1]
			}
		}
	}

	return cstc, nil
}

// Реализация метода SetKey из интерфейса SymmetricAlgorithm
func (cstc *CryptoSymmetricContext) SetKey(key []byte) error {
	if cstc.cipher == nil {
		return errors.New("cipher not initialized")
	}
	return cstc.cipher.SetKey(key)
}

// Реализация метода Encrypt из интерфейса SymmetricAlgorithm

func (cstc *CryptoSymmetricContext) Encrypt(data []byte) ([]byte, error) {
	// Проверка входных данных
	if data == nil || len(data) == 0 {
		return nil, errors.New("data cannot be nil or empty")
	}

	// Добавление набивки
	dataPadded, err := cstc.AddPadding(data)
	if err != nil {
		return nil, fmt.Errorf("failed to add padding: %v", err)
	}

	var encrypted []byte

	// Шифрование в зависимости от режима
	switch cstc.mode {
	case ECB:
		encrypted, err = cstc.encryptECB(dataPadded)
	case CBC:
		encrypted, err = cstc.encryptCBC(dataPadded)
	case PCBC:
		encrypted, err = cstc.encryptPCBC(dataPadded)
	case CFB:
		encrypted, err = cstc.encryptCFB(dataPadded)
	case OFB:
		encrypted, err = cstc.encryptOFB(dataPadded)
	case CTR:
		encrypted, err = cstc.encryptCTR(dataPadded)
	case RandomDelta:
		encrypted, err = cstc.encryptRandomDelta(dataPadded)
	default:
		err = errors.New("unsupported cipher mode")
	}

	if err != nil {
		return nil, fmt.Errorf("encryption failed: %v", err)
	}

	return encrypted, nil
}

// Реализация метода Decrypt из интерфейса SymmetricAlgorithm
func (cstc *CryptoSymmetricContext) Decrypt(data []byte) ([]byte, error) {
	// Проверка входных данных
	if data == nil || len(data) == 0 {
		return nil, errors.New("data cannot be nil or empty")
	}

	var decrypted []byte
	var err error

	// Дешифрование в зависимости от режима
	switch cstc.mode {
	case ECB:
		decrypted, err = cstc.decryptECB(data)
	case CBC:
		decrypted, err = cstc.decryptCBC(data)
	case PCBC:
		decrypted, err = cstc.decryptPCBC(data)
	case CFB:
		decrypted, err = cstc.decryptCFB(data)
	case OFB:
		decrypted, err = cstc.decryptOFB(data)
	case CTR:
		decrypted, err = cstc.decryptCTR(data)
	case RandomDelta:
		decrypted, err = cstc.decryptRandomDelta(data)
	default:
		err = errors.New("unsupported cipher mode")
	}

	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Удаление набивки
	decrypted, err = cstc.RemovePadding(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to remove padding: %v", err)
	}

	return decrypted, nil
}

// Асинхронное шифрование
func (cstc *CryptoSymmetricContext) EncryptAsync(data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1) // Канал для результата
	errorChan := make(chan error, 1)   // Буферизованный канал для ошибок

	go func() {
		defer close(resultChan)
		defer close(errorChan)

		encrypted, err := cstc.Encrypt(data)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- encrypted
	}()

	return resultChan, errorChan
}

// Асинхронное дешифрование
func (cstc *CryptoSymmetricContext) DecryptAsync(data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1) // Канал для результата
	errorChan := make(chan error, 1)   // Буферизованный канал для ошибок

	go func() {
		defer close(resultChan)
		defer close(errorChan)

		decrypted, err := cstc.Decrypt(data)
		if err != nil {
			errorChan <- err
			return
		}
		resultChan <- decrypted
	}()

	return resultChan, errorChan
}

func (cstc *CryptoSymmetricContext) EncryptToFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Читаем весь файл
	data, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	// Шифруем данные, используя выбранный режим и набивку
	encryptedData, err := cstc.Encrypt(data)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	// Записываем зашифрованные данные в выходной файл
	if _, err := outputFile.Write(encryptedData); err != nil {
		return fmt.Errorf("failed to write to output file: %v", err)
	}

	return nil
}
func (cstc *CryptoSymmetricContext) DecryptFromFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	// Читаем весь файл
	data, err := io.ReadAll(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %v", err)
	}

	// Дешифруем данные, используя выбранный режим и удаляя набивку
	decryptedData, err := cstc.Decrypt(data)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}

	// Записываем расшифрованные данные в выходной файл
	if _, err := outputFile.Write(decryptedData); err != nil {
		return fmt.Errorf("failed to write to output file: %v", err)
	}

	return nil
}

// Реализация режима ECB с распараллеливанием
func (cstc *CryptoSymmetricContext) encryptECB(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize

	// Проверка, что длина данных кратна размеру блока
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data length (%d) is not a multiple of block size (%d)", len(data), blockSize)
	}

	numBlocks := len(data) / blockSize
	encrypted := make([]byte, len(data))

	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(blockIndex int) {
			defer wg.Done()
			bs := blockIndex * blockSize
			block := data[bs : bs+blockSize]

			// Используем метод Encrypt из SymmetricAlgorithm
			encryptedBlock, err := cstc.cipher.Encrypt(block)
			if err != nil {
				errChan <- fmt.Errorf("encryption failed at block %d: %w", blockIndex, err)
				return
			}
			copy(encrypted[bs:], encryptedBlock)
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Проверяем наличие ошибок
	if err, ok := <-errChan; ok {
		return nil, err
	}

	return encrypted, nil
}

func (cstc *CryptoSymmetricContext) decryptECB(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize

	// Проверка, что длина данных кратна размеру блока
	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data length (%d) is not a multiple of block size (%d)", len(data), blockSize)
	}

	numBlocks := len(data) / blockSize
	decrypted := make([]byte, len(data))

	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(blockIndex int) {
			defer wg.Done()
			bs := blockIndex * blockSize
			block := data[bs : bs+blockSize]

			// Используем метод Decrypt из SymmetricAlgorithm
			decryptedBlock, err := cstc.cipher.Decrypt(block)
			if err != nil {
				errChan <- fmt.Errorf("decryption failed at block %d: %w", blockIndex, err)
				return
			}
			copy(decrypted[bs:], decryptedBlock)
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Проверяем наличие ошибок
	if err, ok := <-errChan; ok {
		return nil, err
	}

	return decrypted, nil
}

// Реализация режима CBC без распараллеливания
func (cstc *CryptoSymmetricContext) encryptCBC(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize
	if len(cstc.iv) != blockSize {
		return nil, errors.New("invalid IV size")
	}

	encrypted := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	previous := make([]byte, blockSize)
	copy(previous, cstc.iv)

	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		block := data[start : start+blockSize]

		// XOR текущего блока с предыдущим зашифрованным блоком
		inputBlock := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			inputBlock[j] = block[j] ^ previous[j]
		}

		// Шифруем блок
		encryptedBlock, err := cstc.cipher.Encrypt(inputBlock)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at block %d: %w", i, err)
		}

		copy(encrypted[start:], encryptedBlock)
		copy(previous, encryptedBlock)
	}

	return encrypted, nil
}

func (cstc *CryptoSymmetricContext) decryptCBC(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize
	if len(cstc.iv) != blockSize {
		return nil, fmt.Errorf("invalid IV size: expected %d, got %d", blockSize, len(cstc.iv))
	}

	if len(data)%blockSize != 0 {
		return nil, fmt.Errorf("data length (%d) is not a multiple of block size (%d)", len(data), blockSize)
	}

	decrypted := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	previous := make([]byte, blockSize)
	copy(previous, cstc.iv)

	for i := 0; i < numBlocks; i++ {
		start := i * blockSize
		block := data[start : start+blockSize]

		// Расшифровка текущего блока
		decryptedBlock, err := cstc.cipher.Decrypt(block)
		if err != nil {
			return nil, fmt.Errorf("decryption failed at block %d: %w", i, err)
		}

		// XOR с предыдущим зашифрованным блоком
		for j := 0; j < blockSize; j++ {
			decrypted[start+j] = decryptedBlock[j] ^ previous[j]
		}

		// Обновляем previous для следующего блока
		copy(previous, block)
	}

	return decrypted, nil
}

// Реализация режима PCBC без распараллеливания
func (cstc *CryptoSymmetricContext) encryptPCBC(data []byte) ([]byte, error) {
	// Из-за зависимости между блоками распараллеливание ограничено
	blockSize := cstc.blockSize
	if len(cstc.iv) != blockSize {
		return nil, errors.New("invalid IV size")
	}

	encrypted := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	previousPlaintext := make([]byte, blockSize)
	previousCiphertext := make([]byte, blockSize)
	copy(previousCiphertext, cstc.iv)

	for i := 0; i < numBlocks; i++ {
		bs := i * blockSize
		plaintextBlock := data[bs : bs+blockSize]

		// XOR текущего блока с предыдущими
		inputBlock := make([]byte, blockSize)
		for j := 0; j < blockSize; j++ {
			inputBlock[j] = plaintextBlock[j] ^ previousPlaintext[j] ^ previousCiphertext[j]
		}

		// Заменяем вызов transform.Encryption на cipher.Encrypt
		encryptedBlock, err := cstc.cipher.Encrypt(inputBlock)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at block %d: %w", i, err)
		}

		copy(encrypted[bs:], encryptedBlock)
		copy(previousPlaintext, plaintextBlock)
		copy(previousCiphertext, encryptedBlock)
	}

	return encrypted, nil
}

func (cstc *CryptoSymmetricContext) decryptPCBC(data []byte) ([]byte, error) {
	// Из-за зависимости между блоками распараллеливание ограничено
	blockSize := cstc.blockSize
	if len(cstc.iv) != blockSize {
		return nil, errors.New("invalid IV size")
	}

	decrypted := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	previousPlaintext := make([]byte, blockSize)
	previousCiphertext := make([]byte, blockSize)
	copy(previousCiphertext, cstc.iv)

	for i := 0; i < numBlocks; i++ {
		bs := i * blockSize
		block := data[bs : bs+blockSize]

		// Заменяем вызов transform.Decryption на cipher.Decrypt
		decryptedBlock, err := cstc.cipher.Decrypt(block)
		if err != nil {
			return nil, fmt.Errorf("decryption failed at block %d: %w", i, err)
		}

		for j := 0; j < blockSize; j++ {
			decrypted[bs+j] = decryptedBlock[j] ^ previousPlaintext[j] ^ previousCiphertext[j]
		}

		copy(previousPlaintext, decrypted[bs:bs+blockSize])
		copy(previousCiphertext, block)
	}

	return decrypted, nil
}

// Реализация режима CFB с распараллеливанием
func (cstc *CryptoSymmetricContext) encryptCFB(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize
	if len(cstc.iv) != blockSize {
		return nil, errors.New("invalid IV size")
	}

	encrypted := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	feedback := make([]byte, blockSize)
	copy(feedback, cstc.iv)

	for i := 0; i < numBlocks; i++ {
		bs := i * blockSize
		plaintextBlock := data[bs : bs+blockSize]

		// Используем метод Encrypt из SymmetricAlgorithm для получения выходного блока
		outputBlock, err := cstc.cipher.Encrypt(feedback)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at block %d: %w", i, err)
		}

		for j := 0; j < blockSize; j++ {
			encrypted[bs+j] = plaintextBlock[j] ^ outputBlock[j]
		}

		copy(feedback, encrypted[bs:bs+blockSize])
	}

	return encrypted, nil
}

func (cstc *CryptoSymmetricContext) decryptCFB(data []byte) ([]byte, error) {
	// Из-за цепочки зависимостей распараллеливание ограничено
	blockSize := cstc.blockSize
	if len(cstc.iv) != blockSize {
		return nil, errors.New("invalid IV size")
	}

	decrypted := make([]byte, len(data))
	numBlocks := len(data) / blockSize
	feedback := make([]byte, blockSize)
	copy(feedback, cstc.iv)

	for i := 0; i < numBlocks; i++ {
		bs := i * blockSize
		ciphertextBlock := data[bs : bs+blockSize]

		// Используем метод Encrypt из SymmetricAlgorithm для получения выходного блока
		outputBlock, err := cstc.cipher.Encrypt(feedback)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at block %d: %w", i, err)
		}

		for j := 0; j < blockSize; j++ {
			decrypted[bs+j] = ciphertextBlock[j] ^ outputBlock[j]
		}

		copy(feedback, ciphertextBlock)
	}

	return decrypted, nil
}

func (cstc *CryptoSymmetricContext) encryptOFB(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize
	if len(cstc.iv) != blockSize {
		return nil, errors.New("invalid IV size")
	}

	encrypted := make([]byte, len(data))
	feedback := make([]byte, blockSize)
	copy(feedback, cstc.iv)
	//fmt.Printf("Используемый IV: %x\n", cstc.iv)
	for i := 0; i < len(data); i += blockSize {
		// Шифруем текущий `feedback`
		outputBlock, err := cstc.cipher.Encrypt(feedback)
		if err != nil {
			return nil, fmt.Errorf("encryption failed at block %d: %w", i/blockSize, err)
		}

		// XOR текущего блока данных с зашифрованным `feedback`
		for j := 0; j < blockSize && i+j < len(data); j++ {
			encrypted[i+j] = data[i+j] ^ outputBlock[j]
		}

		// Обновляем `feedback`
		copy(feedback, outputBlock)
	}

	return encrypted, nil
}

func (cstc *CryptoSymmetricContext) decryptOFB(data []byte) ([]byte, error) {
	// OFB режим симметричен для шифрования и дешифрования
	return cstc.encryptOFB(data)
}

// Реализация режима CTR с распараллеливанием
func (cstc *CryptoSymmetricContext) encryptCTR(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize
	if len(cstc.iv) != blockSize {
		return nil, errors.New("invalid IV size")
	}

	numBlocks := (len(data) + blockSize - 1) / blockSize
	encrypted := make([]byte, len(data))

	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)
	mutex := &sync.Mutex{} // Для синхронизации доступа к `counter`

	counter := make([]byte, blockSize)
	copy(counter, cstc.iv)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(blockIndex int) {
			defer wg.Done()

			// Инкрементируем счетчик на номер блока
			mutex.Lock()
			currentCounter := make([]byte, blockSize)
			copy(currentCounter, counter)
			incrementCounter(currentCounter, blockIndex)
			mutex.Unlock()

			// Шифруем текущий счетчик для получения keystream блока
			keystreamBlock, err := cstc.cipher.Encrypt(currentCounter)
			if err != nil {
				errChan <- fmt.Errorf("encryption failed at block %d: %w", blockIndex, err)
				return
			}

			bs := blockIndex * blockSize
			be := bs + blockSize
			if be > len(data) {
				be = len(data)
			}

			chunkSize := be - bs
			for j := 0; j < chunkSize; j++ {
				encrypted[bs+j] = data[bs+j] ^ keystreamBlock[j]
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Проверяем наличие ошибок
	if err, ok := <-errChan; ok {
		return nil, err
	}

	return encrypted, nil
}

func (cstc *CryptoSymmetricContext) decryptCTR(data []byte) ([]byte, error) {
	// CTR режим симметричен для шифрования и дешифрования
	return cstc.encryptCTR(data)
}

// Дополнительная функция для инкрементации счетчика с учетом номера блока
func incrementCounter(counter []byte, blockIndex int) {
	// Инкрементируем счетчик на значение blockIndex
	carry := blockIndex
	for i := len(counter) - 1; i >= 0 && carry > 0; i-- {
		sum := int(counter[i]) + (carry & 0xFF)
		counter[i] = byte(sum & 0xFF)
		carry = (carry >> 8) + (sum >> 8)
	}
}

func (cstc *CryptoSymmetricContext) encryptRandomDelta(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize
	encrypted := make([]byte, len(data))

	// Генерация delta
	delta := make([]byte, blockSize)
	if _, err := rand.Read(delta); err != nil {
		return nil, fmt.Errorf("failed to generate delta: %w", err)
	}

	// Шифрование блоков
	for i := 0; i < len(data); i += blockSize {
		blockEnd := i + blockSize
		if blockEnd > len(data) {
			blockEnd = len(data) // Для последнего неполного блока
		}

		block := data[i:blockEnd]
		for j := 0; j < len(block); j++ {
			encrypted[i+j] = block[j] + delta[j%blockSize]
		}
	}

	// Сохраняем `delta` в зашифрованные данные (например, в начало файла)
	return append(delta, encrypted...), nil
}

func (cstc *CryptoSymmetricContext) decryptRandomDelta(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize

	// Извлечение `delta` из данных
	if len(data) < blockSize {
		return nil, errors.New("data too short to contain delta")
	}
	delta := data[:blockSize]
	data = data[blockSize:]

	decrypted := make([]byte, len(data))

	// Дешифрование блоков
	for i := 0; i < len(data); i += blockSize {
		blockEnd := i + blockSize
		if blockEnd > len(data) {
			blockEnd = len(data) // Для последнего неполного блока
		}

		block := data[i:blockEnd]
		for j := 0; j < len(block); j++ {
			decrypted[i+j] = block[j] - delta[j%blockSize]
		}
	}

	return decrypted, nil
}

// Реализация методов добавления и удаления набивки
func (cstc *CryptoSymmetricContext) AddPadding(data []byte) ([]byte, error) {
	blockSize := cstc.blockSize
	paddingLen := blockSize - (len(data) % blockSize)
	if paddingLen == 0 {
		paddingLen = blockSize
	}

	switch cstc.padding {
	case Zeros:
		return ZerosPadding(data, paddingLen), nil
	case ANSIX923:
		return ANSIX923Padding(data, paddingLen), nil
	case PKCS7:
		return PKCS7Padding(data, paddingLen), nil
	case ISO10126:
		return ISO10126Padding(data, paddingLen)
	default:
		return nil, errors.New("unsupported padding mode")
	}
}

func (cstc *CryptoSymmetricContext) RemovePadding(data []byte) ([]byte, error) {
	switch cstc.padding {
	case Zeros:
		return removeZerosPadding(data), nil
	case ANSIX923:
		return removeANSIX923Padding(data)
	case PKCS7:
		return removePKCS7Padding(data)
	case ISO10126:
		return removeISO10126Padding(data)
	default:
		return nil, errors.New("unsupported padding mode")
	}
}

// Реализация функций набивки и удаления набивки

func ZerosPadding(data []byte, paddingLen int) []byte {
	padding := bytes.Repeat([]byte{0}, paddingLen)
	return append(data, padding...)
}

func removeZerosPadding(data []byte) []byte {
	return bytes.TrimRight(data, "\x00")
}

func ANSIX923Padding(data []byte, paddingLen int) []byte {
	padding := append(bytes.Repeat([]byte{0}, paddingLen-1), byte(paddingLen))
	return append(data, padding...)
}

func removeANSIX923Padding(data []byte) ([]byte, error) {
	paddingLen := int(data[len(data)-1])
	if paddingLen > len(data) {
		return nil, errors.New("invalid padding length")
	}
	return data[:len(data)-paddingLen], nil
}

func PKCS7Padding(data []byte, paddingLen int) []byte {
	if paddingLen < 1 || paddingLen > 255 {
		panic("paddingLen must be between 1 and 255")
	}
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	return append(data, padding...)
}

func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen == 0 || paddingLen > len(data) {
		return nil, errors.New("invalid padding length")
	}

	for i := 1; i <= paddingLen; i++ {
		if data[len(data)-i] != byte(paddingLen) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}
	return data[:len(data)-paddingLen], nil
}

func ISO10126Padding(data []byte, paddingLen int) ([]byte, error) {
	if paddingLen < 1 || paddingLen > 255 {
		return nil, errors.New("paddingLen must be between 1 and 255")
	}
	padding := make([]byte, paddingLen)
	if _, err := rand.Read(padding[:paddingLen-1]); err != nil {
		return nil, err
	}
	padding[paddingLen-1] = byte(paddingLen)
	return append(data, padding...), nil
}

func removeISO10126Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}

	paddingLen := int(data[len(data)-1])
	if paddingLen == 0 || paddingLen > len(data) {
		return nil, errors.New("invalid padding length")
	}

	// В ISO10126 остальные байты набивки случайны, поэтому проверяем только последний байт
	return data[:len(data)-paddingLen], nil
}

// Реализация дополнительных методов шифрования и дешифрования для файлов с поддержкой асинхронности

func (cstc *CryptoSymmetricContext) EncryptFileAsync(inputPath, outputPath string) <-chan error {
	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		err := cstc.encryptFile(inputPath, outputPath)
		if err != nil {
			errChan <- err
		}
	}()
	return errChan
}

func (cstc *CryptoSymmetricContext) encryptFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	blockSize := cstc.blockSize
	bufferSize := blockSize * 1024 // Размер буфера для чтения
	buffer := make([]byte, bufferSize)
	pendingData := make([]byte, 0)

	for {
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		pendingData = append(pendingData, buffer[:n]...)

		// Обрабатываем полные блоки
		for len(pendingData) >= blockSize {
			block := pendingData[:blockSize]
			encryptedBlock, err := cstc.cipher.Encrypt(block)
			if err != nil {
				return fmt.Errorf("encryption failed: %v", err)
			}
			if _, err := outputFile.Write(encryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
			pendingData = pendingData[blockSize:]
		}

		if err == io.EOF {
			break
		}
	}

	// Обработка оставшихся данных с добавлением набивки
	if len(pendingData) > 0 {
		paddedData, err := cstc.AddPadding(pendingData)
		if err != nil {
			return fmt.Errorf("failed to add padding: %v", err)
		}
		for len(paddedData) >= blockSize {
			block := paddedData[:blockSize]
			encryptedBlock, err := cstc.cipher.Encrypt(block)
			if err != nil {
				return fmt.Errorf("encryption failed: %v", err)
			}
			if _, err := outputFile.Write(encryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
			paddedData = paddedData[blockSize:]
		}
	} else {
		// Если длина данных кратна размеру блока, добавляем полный блок набивки
		paddedData, err := cstc.AddPadding(nil)
		if err != nil {
			return fmt.Errorf("failed to add padding: %v", err)
		}
		if len(paddedData) > 0 {
			encryptedBlock, err := cstc.cipher.Encrypt(paddedData)
			if err != nil {
				return fmt.Errorf("encryption failed: %v", err)
			}
			if _, err := outputFile.Write(encryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
		}
	}

	return nil
}

func (cstc *CryptoSymmetricContext) DecryptFileAsync(inputPath, outputPath string) <-chan error {
	errChan := make(chan error, 1)
	go func() {
		defer close(errChan)
		err := cstc.decryptFile(inputPath, outputPath)
		if err != nil {
			errChan <- err
		}
	}()
	return errChan
}

func (cstc *CryptoSymmetricContext) decryptFile(inputPath, outputPath string) error {
	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %v", err)
	}
	defer inputFile.Close()

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer outputFile.Close()

	blockSize := cstc.blockSize
	bufferSize := blockSize * 1024 // Размер буфера для чтения
	buffer := make([]byte, bufferSize)
	pendingData := make([]byte, 0)

	for {
		n, err := inputFile.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read input file: %v", err)
		}

		pendingData = append(pendingData, buffer[:n]...)

		// Обрабатываем все блоки, кроме последнего
		for len(pendingData) >= blockSize*2 {
			block := pendingData[:blockSize]
			decryptedBlock, err := cstc.cipher.Decrypt(block)
			if err != nil {
				return fmt.Errorf("decryption failed: %v", err)
			}
			if _, err := outputFile.Write(decryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
			pendingData = pendingData[blockSize:]
		}

		if err == io.EOF {
			break
		}
	}

	// Обработка оставшихся данных
	if len(pendingData) > 0 {
		if len(pendingData)%blockSize != 0 {
			return fmt.Errorf("encrypted data is not a multiple of block size")
		}

		// Дешифруем все оставшиеся блоки
		for len(pendingData) > 0 {
			block := pendingData[:blockSize]
			decryptedBlock, err := cstc.cipher.Decrypt(block)
			if err != nil {
				return fmt.Errorf("decryption failed: %v", err)
			}
			pendingData = pendingData[blockSize:]

			// Если это последний блок, удаляем набивку
			if len(pendingData) == 0 {
				decryptedBlock, err = cstc.RemovePadding(decryptedBlock)
				if err != nil {
					return fmt.Errorf("failed to remove padding: %v", err)
				}
			}

			if _, err := outputFile.Write(decryptedBlock); err != nil {
				return fmt.Errorf("failed to write to output file: %v", err)
			}
		}
	}

	return nil
}
