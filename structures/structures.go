package structures

import (
	"crypto/rsa"
	"encoding/json"
	"log"
)

type User struct {
	Username  []byte
	Password  []byte
	Id        string
	IndexList map[string][]string
	AesKey    []byte
	ClientPub *rsa.PublicKey
}

func Marshal(obj interface{}) []byte {
	content, err := json.Marshal(obj)
	if err != nil {
		log.Fatal(err)
	}
	return content
}

func Unmarshal(data []byte, v interface{}){
	err := json.Unmarshal(data, v)
	if err != nil {
		log.Fatal(err)
	}
}