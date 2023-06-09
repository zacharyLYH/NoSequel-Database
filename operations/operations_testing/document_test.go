package operations_testing

import (
	st "NoSequel/structures"
	util "NoSequel/utils"
	"errors"
	"os"
	"testing"
	// "log"
)

func testCreateDocument(username, password, colPath string, data map[string]interface{}, aes []byte) error {
	resp := CreateDocument_testutil(aes, username, password, colPath, data)
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

func TestReadDocument(t *testing.T) {
	person := st.TestData{
		Username:    "bob",
		Password:    "12345",
		ExpectedUid: "2",
	}
	expectedDocument := map[string]interface{}{
		"DocId": "2-0-0-0",
		"name":  "Alice",
		"age":   28,
		"email": "alice@example.com",
	}
	e := ReadDocument_testutil(person.Username, person.Password, person.ExpectedUid+"-0-0", "2-0-0-0", expectedDocument)
	LogError(e, t)
}

func TestUpdateDocument(t *testing.T) {
	person := st.TestData{
		Username:    "bob",
		Password:    "12345",
		ExpectedUid: "2",
	}
	updatedDocument := map[string]interface{}{
		"DocId": "2-0-0-0",
		"name":  "Alice",
		"age":   30,
		"email": "alice@wonderland.com",
	}
	e := UpdateDocument_testutil(person.Username, person.Password, person.ExpectedUid+"-0-0", updatedDocument)
	LogError(e, t)
}

func TestDeleteDocument(t *testing.T) {
	person := st.TestData{
		Username:    "bob",
		Password:    "12345",
		ExpectedUid: "2",
	}
	data := map[string]interface{}{
		"name":  "NewData",
		"age":   28,
		"email": "NewData@example.com",
	}
	user, _ := SignIn_testutil(person.Username, person.Password)
	person.Aes = user.AesKey
	e := testCreateDocument(person.Username, person.Password, person.ExpectedUid+"-0-0", data, person.Aes)
	LogError(e, t)
	e = DeleteDocument_testutil(person.Username, person.Password, person.ExpectedUid+"-0-0", person.ExpectedUid+"-0-0-1")
	LogError(e, t)
	//DON'T FORGET TO CHANGE 2-0-0.json's NextDocID BACK TO 1.
}
