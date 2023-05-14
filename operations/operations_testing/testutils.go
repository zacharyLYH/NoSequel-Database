package operations_testing

import (
	doc "NoSequel/operations/documents"
	nd "NoSequel/operations/nonDocuments"
	st "NoSequel/structures"
	util "NoSequel/utils"
	crytpRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"reflect"
	"testing"
	// "reflect"
	// "fmt"
)

// Used only for testing.
func CreateKeyAndSave_testutil() {
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

// Takes a username and password then returns an aeskey and error
func SignIn_testutil(username, password string) (st.User, error) {
	CreateKeyAndSave_testutil()
	serverPublicKey := util.ExtractPubKey("serverPublic.pem")
	signIn := st.User{
		Username:  util.EncryptRSA(serverPublicKey, []byte(username)),
		Password:  util.EncryptRSA(serverPublicKey, []byte(password)),
		ClientPub: util.ExtractPubKey("desktopPublic.pem"),
	}
	signInResult := nd.SignIn(st.Marshal(signIn))
	result := st.User{}
	if signInResult.Status != "200" {
		return result, errors.New("sign in failed")
	}
	decryptResult := util.DecryptRSA(signInResult.Data, util.ExtractPrivKey("desktopPrivate.pem"))
	st.Unmarshal(decryptResult, &result)
	if len(result.AesKey) != 32 {
		return result, errors.New("sign in failed")
	}
	return result, nil
}

func Register_testutil(username, password string) {
	nd.RegisterUser(username, password)
}

func CreateIndex_testutil(aes []byte, username, password, indexname string) error {
	encryptedIndexName := util.EncryptAES([]byte(indexname), aes)
	encryptedPassword := util.EncryptAES([]byte(password), aes)
	resp := nd.RegisterIndex(encryptedIndexName, encryptedPassword, username)
	if resp.Status != "200" {
		return errors.New(string(resp.Message))
	}
	return nil
}

func CreateCollection_testutil(aes []byte, username, password, indexname, colname string) error {
	encryptedIndexName := util.EncryptAES([]byte(indexname), aes)
	encryptedPassword := util.EncryptAES([]byte(password), aes)
	encryptedColName := util.EncryptAES([]byte(colname), aes)
	resp := nd.RegisterCollection(username, encryptedIndexName, encryptedColName, encryptedPassword)
	if resp.Status != "200" {
		return errors.New(string(resp.Message))
	}
	return nil
}

func LogError(e error, t *testing.T) {
	if e != nil {
		t.Errorf(e.Error())
	}
}

func CreateDocument_testutil(username, password, colPath string, data map[string]interface{}) st.Response {
	user, _ := SignIn_testutil(username, password)
	encryptPassword := util.EncryptAES(password, user.AesKey)
	encryptColPath := util.EncryptAES(colPath, user.AesKey)
	jsonPayload := st.Marshal(data)
	encryptPayload := util.EncryptAES(jsonPayload, user.AesKey)
	resp := doc.Create(username, encryptPassword, encryptColPath, encryptPayload)
	var raw map[string]interface{}
	st.Unmarshal(util.DecryptAES(user.AesKey, resp.Data), &raw)
	log.Println(raw)
	return resp
}

func ReadDocument_testutil(username, password, colPath, docId string, expectedDocument map[string]interface{}) error {
	user, _ := SignIn_testutil(username, password)
	encryptPassword := util.EncryptAES(password, user.AesKey)
	encryptColPath := util.EncryptAES(colPath, user.AesKey)
	encryptDocId := util.EncryptAES(docId, user.AesKey)
	response := doc.Read(username, encryptPassword, encryptColPath, encryptDocId)
	if response.Status != "200" {
		log.Println(response.Status)
	} else {
		var raw map[string]interface{}
		st.Unmarshal(util.DecryptAES(user.AesKey, response.Data), &raw)
		log.Println(raw)
		// if !compareJson(response.Data, expectedDocument) {
		// 	return errors.New("JSON return doesn't match expected")
		// }
	}
	return nil
}

func UpdateDocument_testutil(username, password, colPath string, data map[string]interface{}) error {
	user, _ := SignIn_testutil(username, password)
	encryptPassword := util.EncryptAES(password, user.AesKey)
	encryptColPath := util.EncryptAES(colPath, user.AesKey)
	jsonPayload := st.Marshal(data)
	encryptPayload := util.EncryptAES(jsonPayload, user.AesKey)
	response := doc.Update(username, encryptPassword, encryptColPath, encryptPayload)
	if response.Status != "200" {
		log.Println(response.Status)
	} else {
		var raw map[string]interface{}
		st.Unmarshal(util.DecryptAES(user.AesKey, response.Data), &raw)
		log.Println(raw)
	}
	return nil
}

func DeleteDocument_testutil(username, password, colPath, docId string) error {
	user, _ := SignIn_testutil(username, password)
	encryptPassword := util.EncryptAES(password, user.AesKey)
	encryptColPath := util.EncryptAES(colPath, user.AesKey)
	encryptDocId := util.EncryptAES(docId, user.AesKey)
	response := doc.Delete(username, encryptPassword, encryptColPath, encryptDocId)
	if response.Status != "200" {
		log.Println(response.Status)
	} else {
		var raw map[string]interface{}
		st.Unmarshal(util.DecryptAES(user.AesKey, response.Data), &raw)
		log.Println(raw)
	}
	return nil
}

func GetMetaData_testutil(username, password string) error {
	user, _ := SignIn_testutil(username, password)
	encryptPassword := util.EncryptAES(password, user.AesKey)
	response := nd.GetMetaData(username, encryptPassword)
	if response.Status != "200" {
		log.Println(response.Status)
	} else {
		var raw map[string]interface{}
		st.Unmarshal(util.DecryptAES(user.AesKey, response.Data), &raw)
		log.Println(raw)
	}
	return nil
}

func TestJSONEquality(expected, actual map[string]interface{}) {
	for key, expectedVal := range expected {
		actualVal, ok := actual[key]
		if !ok {
			log.Printf("actual map does not contain key: %s", key)
			continue
		}
		if !isEqual(expectedVal, actualVal) {
			log.Printf("value mismatch for key: %s, expected: %v, actual: %v", key, expectedVal, actualVal)
			log.Printf("%T, %T", expectedVal, actualVal)
		}
	}
	for key := range actual {
		if _, ok := expected[key]; !ok {
			log.Printf("unexpected key in actual map: %s", key)
		}
	}
}

func isEqual(expected, actual interface{}) bool {
	if reflect.TypeOf(expected) != reflect.TypeOf(actual) {
		switch expected.(type) {
		case int:
			if actualVal, ok := actual.(float64); ok {
				return float64(expected.(int)) == actualVal
			}
		case []int:
			if actualSlice, ok := actual.([]interface{}); ok {
				return compareIntSlices(expected.([]int), actualSlice)
			}
		case []interface{}:
			if actualSlice, ok := actual.([]interface{}); ok {
				return compareSlices(expected.([]interface{}), actualSlice)
			}
		}
		return false
	}
	return reflect.DeepEqual(expected, actual)
}

func compareIntSlices(expected []int, actual []interface{}) bool {
	if len(expected) != len(actual) {
		return false
	}
	for i := range expected {
		if actualVal, ok := actual[i].(float64); ok {
			if float64(expected[i]) != actualVal {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

func compareSlices(expected []interface{}, actual []interface{}) bool {
	if len(expected) != len(actual) {
		return false
	}
	for i := range expected {
		if !isEqual(expected[i], actual[i]) {
			return false
		}
	}
	return true
}
