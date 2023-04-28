package operations_testing

import (
	st "NoSequel/structures"
	util "NoSequel/utils"
	"errors"
	// "log"
	"os"
	"testing"
)

func testCreateDocument(username, password, colPath string, data map[string]interface{}, aes []byte) error {
	resp := CreateDocument_testutil(username, password, colPath, data)
	if resp.Status == "403" {
		return errors.New("Test Create document failed with 403")
	}
	return nil
}

func TestCreateDocument(t *testing.T) {
	person := st.TestData{
		Username:    "danny",
		Password:    "12345",
		ExpectedUid: "3",
	}
	Register_testutil(person.Username, person.Password)
	user, _ := SignIn_testutil(person.Username, person.Password)
	person.Aes = user.AesKey
	e := CreateIndex_testutil(person.Aes, person.Username, person.Password, "MyFirstIndex")
	LogError(e, t)
	e = CreateCollection_testutil(person.Aes, person.Username, person.Password, "MyFirstIndex", "MyFirstCol")
	LogError(e, t)
	data := map[string]interface{}{
		"name":  "Alice",
		"age":   28,
		"email": "alice@example.com",
	}
	e = testCreateDocument(person.Username, person.Password, person.ExpectedUid+"-0-0", data, person.Aes)
	LogError(e, t)
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
	util.DeleteFile("user", person.ExpectedUid, true)
	util.DeleteFile("index", person.ExpectedUid+"-0", true)
	util.DeleteFile("collection", person.ExpectedUid+"-0-0", true)
	util.RemoveLineFromFile(util.FindFolder("admin-user"), person.Username+","+person.ExpectedUid)
}

// func TestReadDocument(t *testing.T) {
// 	person := st.TestData{
// 		Username:    "bob",
// 		Password:    "12345",
// 		ExpectedUid: "2",
// 	}
// 	expectedDocument := map[string]interface{}{
// 		"DocId":"2-0-0-0",
// 		"name":  "Alice",
// 		"age":   28,
// 		"email": "alice@example.com",
// 	}
// 	e := ReadDocument_testutil(person.Username, person.Password, person.ExpectedUid+"-0-0", "2-0-0-0", expectedDocument)
// 	LogError(e, t)
// }
