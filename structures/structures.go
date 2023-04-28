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
	NextIid   int
}

type Index struct {
	Owner         string
	IndexName     string //descriptive name assigned by the user
	Id            string
	CollectionSet map[string]string //Map of collection natural name to the collection's file path
	NextColId     int
}

type Collection struct {
	Index     string //descriptive index name
	ColName   string
	DocList   map[string]Document //docId: document to save lookup time
	NextDocId int
}

type Document struct {
	DocId string //<uid>-<iid>-<cid>-<did>
	Data  map[string]interface{}
}

type Response struct {
	Message []byte
	Status  string
	Data    []byte
}

type TestData struct {
	Username    string
	Password    string
	Aes         []byte
	ExpectedUid string
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
