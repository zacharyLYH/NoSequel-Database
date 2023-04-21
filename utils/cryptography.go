package utils

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	crytpRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	mathRand "math/rand"
	"os"
	"time"
)

func GenerateSymKey(length int) []byte {
	var seededRand *mathRand.Rand = mathRand.New(
		mathRand.NewSource(time.Now().UnixNano()))
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return b
}

func ExtractPubKey(location string) *rsa.PublicKey {
	key, err := os.ReadFile(location)
	if err != nil {
		log.Fatal(err)
	}
	pemBlock, _ := pem.Decode(key)
	parseResult, _ := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	return parseResult.(*rsa.PublicKey)
}

func ExtractPrivKey(location string) *rsa.PrivateKey {
	key, err := os.ReadFile(location)
	if err != nil {
		log.Fatal(err)
	}
	pemBlock, _ := pem.Decode(key)
	parseResult, _ := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	return parseResult
}

func DecryptRSA(encryptedBytes []byte, privateKey *rsa.PrivateKey) []byte {
	decryptedBytes, err := privateKey.Decrypt(nil, encryptedBytes, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		panic(err)
	}
	return decryptedBytes
}

func EncryptRSA(publicKey *rsa.PublicKey, payload []byte) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		crytpRand.Reader,
		publicKey,
		payload,
		nil)
	if err != nil {
		panic(err)
	}
	return encryptedBytes
}

func EncryptAES(text, key []byte) []byte {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crytpRand.Reader, nonce); err != nil {
		log.Println(err)
	}
	return gcm.Seal(nonce, nonce, text, nil)
}

func DecryptAES(key, ciphertext []byte) string {
	c, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		log.Println(err)
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Println(err)
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Println(err)
	}
	return string(plaintext)
}