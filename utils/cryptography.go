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
	"fmt"
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
		log.Fatal(err)
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
		log.Fatal(err)
	}
	return encryptedBytes
}

func EncryptAES(plaintext interface{}, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Println(err)
	}
	var plainTextBytes []byte
	switch v := plaintext.(type) {
	case []byte:
		plainTextBytes = v
	default:
		plainTextBytes = []byte(fmt.Sprintf("%v", v))
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Println(err)
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(crytpRand.Reader, nonce); err != nil {
		log.Println(err)
	}
	return aesgcm.Seal(nonce, nonce, plainTextBytes, nil)
}

func DecryptAES(key, ciphertext []byte) []byte {
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
	return plaintext
}

func CreatePubPrivPemKey() {
	privatekey, err := rsa.GenerateKey(crytpRand.Reader, 2048)
	if err != nil {
		log.Fatalf("Cannot generate RSA key\n")
		os.Exit(1)
	}
	publickey := &privatekey.PublicKey
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create("desktopPrivate.pem")
	if err != nil {
		log.Fatalf("error when create userPrivate.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		log.Fatalf("error when encode Private pem: %s \n", err)
		os.Exit(1)
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		log.Fatalf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create("desktopPublic.pem")
	if err != nil {
		log.Fatalf("error when create public.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		log.Fatalf("error when encode public pem: %s \n", err)
		os.Exit(1)
	}
}