package algorithm

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// RC5 представляет алгоритм RC5
type RC5 struct {
	S []uint64 // Расширенный ключ
	r int      // Количество раундов
	w uint     // Размер слова в битах
	b int      // Длина ключа в байтах
}

// NewRC5 создает новый экземпляр RC5 с параметрами по умолчанию
func NewRC5() *RC5 {
	return &RC5{
		r: 12, // Количество раундов (можно менять)
		w: 64, // Размер слова в битах (16, 32, 64)
		b: 16, // Длина ключа в байтах (можно менять)
	}
}

// SetKey устанавливает ключ и выполняет расширение ключа
func (rc5 *RC5) SetKey(key []byte) error {
	if len(key) == 0 {
		return errors.New("key cannot be empty")
	}
	rc5.b = len(key)
	rc5.S = rc5.keyExpansion(key)
	return nil
}

// Encrypt шифрует данные
func (rc5 *RC5) Encrypt(data []byte) ([]byte, error) {
	blockSize := rc5.w / 4 // Размер блока в байтах
	if len(data)%int(blockSize) != 0 {
		return nil, fmt.Errorf("data length (%d) is not a multiple of block size (%d)", len(data), blockSize)
	}

	encrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += int(blockSize) {
		block, err := rc5.encryptBlock(data[i : i+int(blockSize)])
		if err != nil {
			return nil, err
		}
		copy(encrypted[i:i+int(blockSize)], block)
	}

	return encrypted, nil
}

// Decrypt дешифрует данные
func (rc5 *RC5) Decrypt(data []byte) ([]byte, error) {
	blockSize := rc5.w / 4 // Размер блока в байтах
	if len(data)%int(blockSize) != 0 {
		return nil, fmt.Errorf("data length (%d) is not a multiple of block size (%d)", len(data), blockSize)
	}

	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += int(blockSize) {
		block, err := rc5.decryptBlock(data[i : i+int(blockSize)])
		if err != nil {
			return nil, err
		}
		copy(decrypted[i:i+int(blockSize)], block)
	}

	return decrypted, nil
}

// Вспомогательные функции

// encryptBlock шифрует один блок данных
func (rc5 *RC5) encryptBlock(block []byte) ([]byte, error) {
	wordSizeBytes := rc5.w / 8 // Размер слова в байтах
	if len(block) != int(wordSizeBytes*2) {
		return nil, fmt.Errorf("block size must be %d bytes", wordSizeBytes*2)
	}

	var A, B uint64
	switch rc5.w {
	case 16:
		A = uint64(binary.LittleEndian.Uint16(block[0:2]))
		B = uint64(binary.LittleEndian.Uint16(block[2:4]))
	case 32:
		A = uint64(binary.LittleEndian.Uint32(block[0:4]))
		B = uint64(binary.LittleEndian.Uint32(block[4:8]))
	case 64:
		A = binary.LittleEndian.Uint64(block[0:8])
		B = binary.LittleEndian.Uint64(block[8:16])
	default:
		return nil, errors.New("unsupported word size")
	}

	A += rc5.S[0]
	B += rc5.S[1]
	for i := 1; i <= rc5.r; i++ {
		A = rol(A^B, B%uint64(rc5.w), uint(rc5.w)) + rc5.S[2*i]
		B = rol(B^A, A%uint64(rc5.w), uint(rc5.w)) + rc5.S[2*i+1]
	}

	encryptedBlock := make([]byte, wordSizeBytes*2)
	switch rc5.w {
	case 16:
		binary.LittleEndian.PutUint16(encryptedBlock[0:2], uint16(A))
		binary.LittleEndian.PutUint16(encryptedBlock[2:4], uint16(B))
	case 32:
		binary.LittleEndian.PutUint32(encryptedBlock[0:4], uint32(A))
		binary.LittleEndian.PutUint32(encryptedBlock[4:8], uint32(B))
	case 64:
		binary.LittleEndian.PutUint64(encryptedBlock[0:8], A)
		binary.LittleEndian.PutUint64(encryptedBlock[8:16], B)
	}

	return encryptedBlock, nil
}

// decryptBlock дешифрует один блок данных
func (rc5 *RC5) decryptBlock(block []byte) ([]byte, error) {
	wordSizeBytes := rc5.w / 8 // Размер слова в байтах
	if len(block) != int(wordSizeBytes*2) {
		return nil, fmt.Errorf("block size must be %d bytes", wordSizeBytes*2)
	}

	var A, B uint64
	switch rc5.w {
	case 16:
		A = uint64(binary.LittleEndian.Uint16(block[0:2]))
		B = uint64(binary.LittleEndian.Uint16(block[2:4]))
	case 32:
		A = uint64(binary.LittleEndian.Uint32(block[0:4]))
		B = uint64(binary.LittleEndian.Uint32(block[4:8]))
	case 64:
		A = binary.LittleEndian.Uint64(block[0:8])
		B = binary.LittleEndian.Uint64(block[8:16])
	default:
		return nil, errors.New("unsupported word size")
	}

	for i := rc5.r; i >= 1; i-- {
		B = ror(B-rc5.S[2*i+1], A%uint64(rc5.w), rc5.w) ^ A
		A = ror(A-rc5.S[2*i], B%uint64(rc5.w), rc5.w) ^ B
	}
	B -= rc5.S[1]
	A -= rc5.S[0]

	decryptedBlock := make([]byte, wordSizeBytes*2)
	switch rc5.w {
	case 16:
		binary.LittleEndian.PutUint16(decryptedBlock[0:2], uint16(A))
		binary.LittleEndian.PutUint16(decryptedBlock[2:4], uint16(B))
	case 32:
		binary.LittleEndian.PutUint32(decryptedBlock[0:4], uint32(A))
		binary.LittleEndian.PutUint32(decryptedBlock[4:8], uint32(B))
	case 64:
		binary.LittleEndian.PutUint64(decryptedBlock[0:8], A)
		binary.LittleEndian.PutUint64(decryptedBlock[8:16], B)
	}

	return decryptedBlock, nil
}

func (rc5 *RC5) keyExpansion(K []byte) []uint64 {
	w := uint(rc5.w)
	r := rc5.r
	b := rc5.b
	t := 2 * (r + 1)

	// Магические константы
	var Pw, Qw uint64
	switch w {
	case 16:
		Pw = 0xb7e1
		Qw = 0x9e37
	case 32:
		Pw = 0xb7e15163
		Qw = 0x9e3779b9
	case 64:
		Pw = 0xb7e151628aed2a6b
		Qw = 0x9e3779b97f4a7c15
	default:
		panic("unsupported word size")
	}

	u := w / 8                     // байт на слово
	c := (b + int(u) - 1) / int(u) // количество слов в L
	L := make([]uint64, c)

	for i := b - 1; i >= 0; i-- {
		L[i/int(u)] = (L[i/int(u)] << 8) + uint64(K[i])
	}

	S := make([]uint64, t)
	S[0] = Pw
	for i := 1; i < t; i++ {
		S[i] = S[i-1] + Qw
	}

	var A, B uint64
	i, j := 0, 0
	n := 3 * max(t, c)
	for k := 0; k < int(n); k++ {
		A = rol(S[i]+A+B, 3, w)
		S[i] = A
		B = rol(L[j]+A+B, (A+B)%uint64(w), w)
		L[j] = B
		i = (i + 1) % int(t)
		j = (j + 1) % int(c)
	}
	return S
}

// Утилиты

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func rol(x, y uint64, w uint) uint64 {
	return ((x << (y % uint64(w))) | (x >> (uint64(w) - (y % uint64(w))))) & ((1 << w) - 1)
}

func ror(x, y uint64, w uint) uint64 {
	return ((x >> (y % uint64(w))) | (x << (uint64(w) - (y % uint64(w))))) & ((1 << w) - 1)
}
