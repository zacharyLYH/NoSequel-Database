package utils

import (
	// "fmt"
	"testing"
)

func TestRSAConnection(t *testing.T) {
	cipherText := EncryptRSA(ExtractPubKey(FindFolder("rsa")+"serverPublic.pem"), []byte("Super secret message"))
	rawMsg := string(DecryptRSA(cipherText, ExtractPrivKey(FindFolder("rsa")+"serverPrivate.pem")))
	if rawMsg != "Super secret message" {
		t.Errorf("RSA: Expected \"Super secret message\", got " + rawMsg)
	}
}

func TestAesConnection(t *testing.T) {
	aesKey := GenerateSymKey(32)
	cipherText := EncryptAES([]byte("Super secret message"), aesKey)
	rawMsg := DecryptAES(aesKey, cipherText)
	if rawMsg != "Super secret message" {
		t.Errorf("AES: Expected \"Super secret message\", got " + rawMsg)
	}
}
