package nondocuments

import (
	st "NoSequel/structures"
	util "NoSequel/utils"
	crytpRand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"strconv"
	"testing"
)

func testRegisterUser(username, password, expectedUid string) (string, error) {
	RegisterUser(username, password)
	uid := ReturnUidFromUsername(username)
	if uid != expectedUid {
		return "", errors.New("Expected" + expectedUid + ", got " + uid)
	}
	data := util.ReadFile("user", uid, true)
	user := st.User{}
	st.Unmarshal(data, &user)
	if string(user.Username) != username {
		return "", errors.New("Expected " + username + ", got " + string(user.Username))
	}
	if string(user.Password) != password {
		return "", errors.New("Expected " + password + " got " + string(user.Password))
	}
	return "", nil
}

func testSignIn(username, password, expectedUid string) ([]byte, error) {
	createKeyAndSave()
	serverPublicKey := util.ExtractPubKey("serverPublic.pem")
	signIn := st.User{
		Username:  util.EncryptRSA(serverPublicKey, []byte(username)),
		Password:  util.EncryptRSA(serverPublicKey, []byte(password)),
		ClientPub: util.ExtractPubKey("desktopPublic.pem"),
	}
	signInResult := SignIn(st.Marshal(signIn))
	decryptResult := util.DecryptRSA(signInResult, util.ExtractPrivKey("desktopPrivate.pem"))
	result := st.User{}
	st.Unmarshal(decryptResult, &result)
	if len(result.AesKey) != 32 {
		return []byte{}, errors.New("Expected 32 byte aeskey, got " + strconv.Itoa(len(result.AesKey)))
	}
	if result.Id != expectedUid {
		return []byte{}, errors.New("Expected " + expectedUid + ", got " + result.Id)
	}
	if string(result.Username) != username {
		return []byte{}, errors.New("Expected " + username + ", got " + string(result.Username))
	}
	return result.AesKey, nil
}

func testCreateIndex(aes []byte, username, password, indexname string) error {
	encryptedIndexName := util.EncryptAES([]byte(indexname), aes)
	encryptedPassword := util.EncryptAES([]byte(password), aes)
	resp := RegisterIndex(encryptedIndexName, encryptedPassword, username)
	if resp.Status != "200" {
		return errors.New(string(resp.Message))
	}
	return nil
}

func TestCreateIndex(t *testing.T) {
	_, e := testRegisterUser("carlos", "12345", "3")
	if e != nil {
		t.Errorf(e.Error())
	}
	aes, e := testSignIn("carlos", "12345", "3")
	if e != nil {
		t.Errorf(e.Error())
	}
	e = testCreateIndex(aes, "carlos", "12345", "MyFirstIndex")
	if e != nil {
		t.Errorf(e.Error())
	}
	e = testCreateIndex(aes, "carlos", "12345", "MyFirstIndex")
	if e != nil {
		if e.Error() != "Attempting to create duplicate index" {
			t.Errorf(e.Error())
		}
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
	util.DeleteFile("user", "3", true)
	util.DeleteFile("index", "3-0", true)
	util.RemoveLineFromFile(util.FindFolder("admin-user"), "carlos,3")
}

// Used only for testing.
func createKeyAndSave() {
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
