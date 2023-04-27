package utils

import (
	st "NoSequel/structures"
	"bytes"
	"testing"
	"log"
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
	if string(rawMsg) != "Super secret message" {
		t.Errorf("AES: Expected \"Super secret message\", got " + string(rawMsg))
	}
	sampleJSON := map[string]interface{}{
		"name":  "Jane Doe",
		"age":   30,
		"email": "jane.doe@example.com",
		"address": map[string]interface{}{
			"street":     "123 Main St",
			"city":       "Anytown",
			"state":      "CA",
			"postalCode": "12345",
		},
		"phoneNumbers": []map[string]interface{}{
			{
				"type":   "home",
				"number": "555-555-1234",
			},
			{
				"type":   "work",
				"number": "555-555-5678",
			},
		},
		"isStudent": false,
	}
	plainText := st.Marshal(sampleJSON)
	encryptedJson := EncryptAES(plainText, aesKey)
	decipherJson := DecryptAES(aesKey, encryptedJson)
	if !bytes.Equal([]byte(plainText), decipherJson) {
		t.Errorf("AES: Interface deciphering is faulty")
	}
	var unmarshallJson map[string]interface{}
	st.Unmarshal(decipherJson, &unmarshallJson)
	log.Println(unmarshallJson["name"])
}
