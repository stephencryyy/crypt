package algorithm

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)


func GeneratePrime(bits int) (*big.Int, error) {
	prime, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	//	fmt.Printf("Сгенерированное простое число (prime): %s\n", prime.String())
	return prime, nil
}

// Генерирует приватный ключ (случайное число меньше prime)
func GeneratePrivateKey(prime *big.Int) (*big.Int, error) {
	privateKey, err := rand.Int(rand.Reader, prime)
	if err != nil {
		return nil, err
	}
	//	fmt.Printf("Сгенерированный приватный ключ: %s\n", privateKey.String())
	return privateKey, nil
}

// Публичный ключ g^privateKey mod p
func GeneratePublicKey(g, privateKey, prime *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(g, privateKey, prime)
	//	fmt.Printf("Сгенерированный публичный ключ: %s\n", publicKey.String())
	return publicKey
}

// Общий ключ (otherPublicKey ^ privateKey) mod p
func GenerateSharedKey(privateKey, otherPublicKey, prime *big.Int) *big.Int {
	sharedKey := new(big.Int).Exp(otherPublicKey, privateKey, prime)
	//fmt.Printf("Сгенерированный общий ключ (sharedKey): %s\n", sharedKey.String())
	return sharedKey
}

// Хеширует общий ключ с помощью SHA-256
func HashSharedKey(sharedKey *big.Int) []byte {
	hash := sha256.New()
	hash.Write(sharedKey.Bytes())
	hashedKey := hash.Sum(nil)
	//fmt.Printf("Хеш общего ключа (SHA-256): %x\n", hashedKey)
	return hashedKey
}
