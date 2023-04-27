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
	CollectionSet map[string]struct{} //Set of collection folder names. A common pattern we're using is matching file names to determine which file we want to work on. This way, we can avoid loading the entire Collection into memory JUST TO get its name, which is inefficient.
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
	Data  interface{}
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
