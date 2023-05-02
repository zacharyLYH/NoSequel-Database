package documents

import (
	op "NoSequel/operations"
	st "NoSequel/structures"
	util "NoSequel/utils"

	// "log"
	"strconv"
	"strings"
)

/*
Username and password are self explanatory. Password should be aes encrypted.
ColPath is the path to the collection we're interested in working with. We need to check to see if this user indeed owns this collection. We can do so by looking at the index that this collection claims it belongs to by taking the <uid>-<iid> portion out of the colPath which has the form <uid>-<iid>-<cid>.

Upon return from this function, the caller should be confident in the legitamacy of this user's right of modify/create this collection. Subsequently, if a user has right to work with this collection, they can do anything with the documents it encloses.
*/
func verifyCollectionAccess(username string, encryptedPassword, encryptedPathToResource []byte) bool {
	aes := op.GetAesKeyFromUsername(username)
	decryptedColPath := string(util.DecryptAES(aes, encryptedPathToResource))
	if !op.CheckCredentials(username, encryptedPassword) {
		return false
	}
	indexPath := strings.Join(strings.Split(decryptedColPath, "-")[:2], "-") // need to check to make sure split is at least length 2
	index := st.Index{}
	st.Unmarshal(util.ReadFile("index", indexPath, true), &index)
	if index.Owner != username {
		return false
	}
	for _, v := range index.CollectionSet {
		if v == decryptedColPath {
			return true
		}
	}
	return false
}

func Create(username string, password, colPath, payload []byte) st.Response {
	resp := st.Response{}
	if verifyCollectionAccess(username, password, colPath) {
		aes := op.GetAesKeyFromUsername(username)
		decryptedColPath := string(util.DecryptAES(aes, colPath))
		collection := st.Collection{}
		st.Unmarshal(util.ReadFile("collection", decryptedColPath, true), &collection)
		newDoc := st.Document{}
		newDoc.DocId = decryptedColPath + "-" + strconv.Itoa(collection.NextDocId)
		collection.NextDocId++
		var unmarshallJson map[string]interface{}
		st.Unmarshal(util.DecryptAES(aes, payload), &unmarshallJson)
		newDoc.Data = unmarshallJson
		newDoc.Data["DocId"] = newDoc.DocId
		collection.DocList[newDoc.DocId] = newDoc
		util.WriteJsonFile(st.Marshal(collection), util.AssembleFileName("collection", decryptedColPath, true))
		resp.Data = util.EncryptAES(st.Marshal(unmarshallJson), aes)
		resp.Status = "200"
	} else {
		resp.Status = "403"
	}
	return resp
}

func Read(username string, password, colPath, docId []byte) st.Response {
	resp := st.Response{}
	if verifyCollectionAccess(username, password, colPath) {
		aes := op.GetAesKeyFromUsername(username)
		decryptedColPath := string(util.DecryptAES(aes, colPath))
		decryptedDocId := string(util.DecryptAES(aes, docId))
		collection := st.Collection{}
		st.Unmarshal(util.ReadFile("collection", decryptedColPath, true), &collection)
		if _, exists := collection.DocList[decryptedDocId]; exists {
			resp.Data = util.EncryptAES(st.Marshal(collection.DocList[decryptedDocId].Data), aes)
		} else {
			resp.Status = "404"
		}
		resp.Status = "200"
	} else {
		resp.Status = "403"
	}
	return resp
}

// Payload has DocId embedded within it.
func Update(username string, password, colPath, payload []byte) st.Response {
	resp := st.Response{}
	if verifyCollectionAccess(username, password, colPath) {
		aes := op.GetAesKeyFromUsername(username)
		var decryptedPayload map[string]interface{}
		st.Unmarshal(util.DecryptAES(aes, payload), &decryptedPayload)
		decryptedColPath := string(util.DecryptAES(aes, colPath))
		collection := st.Collection{}
		st.Unmarshal(util.ReadFile("collection", decryptedColPath, true), &collection)
		id := decryptedPayload["DocId"].(string)
		if _, exists := collection.DocList[id]; exists {
			doc := st.Document{}
			doc = collection.DocList[id]
			doc.Data = decryptedPayload
			collection.DocList[id] = doc
			util.WriteJsonFile(st.Marshal(collection), util.AssembleFileName("collection", decryptedColPath, true))
			resp.Data = util.EncryptAES(st.Marshal(decryptedPayload), aes)
		} else {
			resp.Status = "404"
		}
		resp.Status = "200"
	} else {
		resp.Status = "403"
	}
	return resp
}

func Delete(username string, password, colPath, docId []byte) st.Response {
	resp := st.Response{}
	if verifyCollectionAccess(username, password, colPath) {
		aes := op.GetAesKeyFromUsername(username)
		decryptedColPath := string(util.DecryptAES(aes, colPath))
		decryptedDocId := string(util.DecryptAES(aes, docId))
		collection := st.Collection{}
		st.Unmarshal(util.ReadFile("collection", decryptedColPath, true), &collection)
		var deleted map[string]interface{}
		if _, exists := collection.DocList[decryptedDocId]; exists {
			deleted = collection.DocList[decryptedDocId].Data
			delete(collection.DocList, decryptedDocId)
			util.WriteJsonFile(st.Marshal(collection), util.AssembleFileName("collection", decryptedColPath, true))
			resp.Data = util.EncryptAES(st.Marshal(deleted), aes)
		} else {
			resp.Status = "404"
		}
	} else {
		resp.Status = "403"
	}
	return resp
}
