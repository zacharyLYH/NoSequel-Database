package operations_testing

import (
	nd "NoSequel/operations/nondocuments"
	doc "NoSequel/operations/documents"
	st "NoSequel/structures"
	util "NoSequel/utils"
	crytpRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"testing"
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
	decryptResult := util.DecryptRSA(signInResult, util.ExtractPrivKey("desktopPrivate.pem"))
	result := st.User{}
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
	user,_ := SignIn_testutil(username, password)
	encryptPassword := util.EncryptAES(password, user.AesKey)
	encryptColPath := util.EncryptAES(colPath, user.AesKey)
	jsonPayload := st.Marshal(data)
	encryptPayload := util.EncryptAES(jsonPayload, user.AesKey)
	return doc.Create(username, encryptPassword, encryptColPath, encryptPayload)
}
