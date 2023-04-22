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
	IndexList []string //list of index folder names
	AesKey    []byte
	ClientPub *rsa.PublicKey
}

type Index struct {
	Owner          string
	IndexName      string //descriptive name assigned by the user
	Id             string
	CollectionList string //list of collection folder names
}

type Response struct {
	Message []byte
	Status  string
}

func Marshal(obj interface{}) []byte {
	content, err := json.Marshal(obj)
	if err != nil {
		log.Fatal(err)
	}
	return content
}

func Unmarshal(data []byte, v interface{}) {
	err := json.Unmarshal(data, v)
	if err != nil {
		log.Fatal(err)
	}
}
