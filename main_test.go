package main

import (
	test_util "NoSequel/operations/operations_testing"
	st "NoSequel/structures"
	util "NoSequel/utils"
	"bytes"
	"encoding/json"

	// "log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/labstack/echo"
)

func TestSayHello(t *testing.T) {
	// Create a new instance of the Echo router
	e := echo.New()
	e.GET("/sayHello", sayHello)
	resp := makeHttpRequestReturnResponse(t, e, st.ServerReceive{}, "GET", "/sayHello")
	// Check the response message
	expectedMessage := "Hello World"
	if string(resp.Message) != expectedMessage {
		t.Errorf("unexpected message: got %s, want %s", string(resp.Message), expectedMessage)
	}
}

func TestRegisterUser(t *testing.T) {
	person := st.TestData{
		Username:    "danny",
		Password:    "12345",
		ExpectedUid: "3",
	}
	// Create a new Echo instance
	e := echo.New()
	// Define the API route
	e.POST("/register", register)
	// Define a mock input object with encrypted values for UsernameByte and PasswordByte
	serverPubKey := util.ExtractPubKey(util.FindFolder("rsa") + "serverPublic.pem")
	input := st.ServerReceive{}
	input.UsernameByte = util.EncryptRSA(serverPubKey, []byte(person.Username))
	input.PasswordByte = util.EncryptRSA(serverPubKey, []byte(person.Password))
	payload := st.Marshal(input)
	// Define a request object with the payload
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	// Create a new recorder to capture the response
	rec := httptest.NewRecorder()
	// Call the API handler function, passing in the request and response recorder
	e.ServeHTTP(rec, req)
	// Check the response status code
	if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: got %v, want %v or %v", rec.Code, http.StatusOK, http.StatusBadRequest)
	}
	// Parse the response body into a Response object
	var resp st.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Errorf("unable to parse response body: %v", err)
	}
	// Check the response message
	if resp.Status == "200" {
		expectedMessage := "Created an account for " + person.Username
		if string(resp.Message) != expectedMessage {
			t.Errorf("unexpected message: got %s, want %s", string(resp.Message), expectedMessage)
		}
		util.DeleteFile("user", person.ExpectedUid, true)
		util.RemoveLineFromFile(util.FindFolder("admin-user"), person.Username+","+person.ExpectedUid)
	} else {
		expectedMessage := ""
		if string(resp.Message) != expectedMessage {
			t.Errorf("unexpected message: got %s, want %s", string(resp.Message), expectedMessage)
		}
	}
}

func TestSignInUser(t *testing.T) {
	person := st.TestData{
		Username:    "alice",
		Password:    "12345",
		ExpectedUid: "1",
	}
	e := echo.New()
	// Define the API route
	e.POST("/signIn", signIn)
	util.CreatePubPrivPemKey()
	serverPublicKey := util.ExtractPubKey("serverPublic.pem")
	signInRequestBody := st.User{
		Username:  util.EncryptRSA(serverPublicKey, []byte(person.Username)),
		Password:  util.EncryptRSA(serverPublicKey, []byte(person.Password)),
		ClientPub: util.ExtractPubKey("desktopPublic.pem"),
	}
	input := st.ServerReceive{}
	input.Payload = st.Marshal(signInRequestBody)
	resp := makeHttpRequestReturnResponse(t, e, input, "POST", "/signIn")
	// Check the response message
	if resp.Status == "200" {
		result := st.User{}
		st.Unmarshal(util.DecryptRSA(resp.Data, util.ExtractPrivKey("desktopPrivate.pem")), &result)
		if len(result.AesKey) != 32 {
			t.Errorf("expected aes key length 32, got %s", strconv.Itoa(len(result.AesKey)))
		}
		if !bytes.Equal(result.Username, []byte(person.Username)) {
			t.Errorf("unexpected message: got %s, want %s", string(result.Username), person.Username)
		}
		if result.Id != person.ExpectedUid {
			t.Errorf("unexpected message: got %s, want %s", string(result.Id), person.ExpectedUid)
		}
	} else {
		t.Errorf("unexpected status: got %s, want %s", resp.Status, "200")
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
}

func TestGetMetaData(t *testing.T) {
	person := st.TestData{
		Username:      "alice",
		Password:      "12345",
		ExpectedUid:   "1",
		ExpectedIndex: []string{"1-0"},
		ExpectedCollection: map[string]string{
			"MyFirstCol":  "1-0-0",
			"MySecondCol": "1-0-1",
		},
	}
	e := echo.New()
	//get aes key
	loggedInUser, _ := test_util.SignIn_testutil(person.Username, person.Password)
	// Define the API route
	e.GET("/getMetaData", getMetaData)
	input := st.ServerReceive{}
	input.UsernameString = person.Username
	input.PasswordByte = util.EncryptAES(person.Password, loggedInUser.AesKey)
	resp := makeHttpRequestReturnResponse(t, e, input, "GET", "/getMetaData")
	if resp.Status == "200" {
		result := make(map[string]interface{})
		st.Unmarshal(util.DecryptAES(loggedInUser.AesKey, resp.Data), &result)
		if len(result["indexs"].([]interface{})) == len(person.ExpectedIndex) {
			for i := 0; i < len(person.ExpectedIndex); i++ {
				found := false
				for j := 0; j < len(result["indexs"].([]interface{})); j++ {
					if person.ExpectedIndex[i] == result["indexs"].([]interface{})[j] {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("unexpected: want %s", person.ExpectedIndex[i])
				}
			}
		} else {
			t.Errorf("unexpected index length: got %d, want %d", len(result["indexs"].([]interface{})), len(person.ExpectedIndex))
		}
		collections := result["collections"]
		if len(collections.(map[string]interface{})) == len(person.ExpectedCollection) {
			for k := range collections.(map[string]interface{}) {
				if _, exists := person.ExpectedCollection[k]; !exists {
					t.Errorf("collections don't have %s", k)
				}
			}
		} else {
			t.Errorf("unexpected col length: got %d, want %d", len(collections.(map[string]interface{})), len(person.ExpectedCollection))
		}
	} else {
		t.Errorf("unexpected status: got %s, want %s", resp.Status, "200")
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
}

func TestCreateIndex(t *testing.T) {
	person := st.TestData{
		Username:       "danny",
		Password:       "12345",
		ExpectedUid:    "3",
		NewIndexName:   "FirstIndexFakeUser",
		NewIndexFileId: "3-0",
	}
	test_util.Register_testutil(person.Username, person.Password)
	dannyUser, _ := test_util.SignIn_testutil(person.Username, person.Password)
	e := echo.New()
	// Define the API route
	e.POST("/createIndex", createIndex)
	input := st.ServerReceive{}
	input.IndexNameByte = util.EncryptAES(person.NewIndexName, dannyUser.AesKey)
	input.PasswordByte = util.EncryptAES(person.Password, dannyUser.AesKey)
	input.UsernameString = person.Username
	resp := makeHttpRequestReturnResponse(t, e, input, "POST", "/createIndex")
	if resp.Status == "200" {
		userData := st.User{}
		st.Unmarshal(util.ReadFile("user", person.ExpectedUid, true), &userData)
		found := false
		for _, idx := range userData.IndexList {
			if idx == person.NewIndexFileId {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("couldn't find %s in the test index", person.NewIndexFileId)
		}
		createdIndex := st.Index{}
		st.Unmarshal(util.ReadFile("index", person.NewIndexFileId, true), &createdIndex)
		if createdIndex.IndexName != person.NewIndexName {
			t.Errorf("new index name is %s; expected %s", createdIndex.IndexName, person.NewIndexName)
		}
		if createdIndex.Owner != person.Username {
			t.Errorf("new index name is %s; expected %s", createdIndex.Owner, person.Username)
		}
	} else {
		t.Errorf("unexpected status: got %s, want %s", resp.Status, "200")
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
	util.DeleteFile("user", person.ExpectedUid, true)
	util.DeleteFile("index", person.NewIndexFileId, true)
	util.RemoveLineFromFile(util.FindFolder("admin-user"), person.Username+","+person.ExpectedUid)
}

func TestCreateCollection(t *testing.T) {
	person := st.TestData{
		Username:       "danny",
		Password:       "12345",
		ExpectedUid:    "3",
		NewIndexName:   "FirstIndexFakeUser",
		NewIndexFileId: "3-0",
		NewColName:     "FirstCollectionYey",
		NewColFileId:   "3-0-0",
	}
	test_util.Register_testutil(person.Username, person.Password)
	dannyUser, _ := test_util.SignIn_testutil(person.Username, person.Password)
	test_util.CreateIndex_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewIndexName)
	e := echo.New()
	// Define the API route
	e.POST("/createCollection", createCollection)
	input := st.ServerReceive{}
	input.IndexNameByte = util.EncryptAES(person.NewIndexName, dannyUser.AesKey)
	input.ColNameByte = util.EncryptAES(person.NewColName, dannyUser.AesKey)
	input.PasswordByte = util.EncryptAES(person.Password, dannyUser.AesKey)
	input.UsernameString = person.Username
	resp := makeHttpRequestReturnResponse(t, e, input, "POST", "/createCollection")
	if resp.Status == "200" {
		index := st.Index{}
		st.Unmarshal(util.ReadFile("index", person.NewIndexFileId, true), &index)
		if value, exists := index.CollectionSet[person.NewColName]; !exists {
			t.Errorf("collection %s wasn't created", person.NewColName)
			if value != person.NewColFileId {
				t.Errorf("collection id %s not equals %s", value, person.NewColName)
			}
		}
		collection := st.Collection{}
		st.Unmarshal(util.ReadFile("collection", person.NewColFileId, true), &collection)
		if collection.ColName != person.NewColName {
			t.Errorf("expected: %s; got: %s ", person.NewColName, collection.ColName)
		}
		if collection.Index != person.NewIndexName {
			t.Errorf("expected: %s; got: %s ", person.NewIndexName, collection.Index)
		}
	} else {
		t.Errorf("unexpected status: got %s, want %s TestCreateCollection", resp.Status, "200")
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
	util.DeleteFile("user", person.ExpectedUid, true)
	util.DeleteFile("index", person.NewIndexFileId, true)
	util.DeleteFile("collection", person.NewColFileId, true)
	util.RemoveLineFromFile(util.FindFolder("admin-user"), person.Username+","+person.ExpectedUid)
}

func TestCreateDocument(t *testing.T) {
	payload := map[string]interface{}{
		"key1": 42,
		"key2": "value",
		"key3": []int{1, 2, 3},
		"key4": map[string]interface{}{
			"nested1": "nested value",
			"nested2": 3.14,
		},
	}
	person := st.TestData{
		Username:       "danny",
		Password:       "12345",
		ExpectedUid:    "3",
		NewIndexName:   "FirstIndexFakeUser",
		NewIndexFileId: "3-0",
		NewColName:     "FirstCollectionYey",
		NewColFileId:   "3-0-0",
		Payload:        payload,
		NewDocumentId:  "3-0-0-0",
	}
	test_util.Register_testutil(person.Username, person.Password)
	dannyUser, _ := test_util.SignIn_testutil(person.Username, person.Password)
	test_util.CreateIndex_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewIndexName)
	test_util.CreateCollection_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewIndexName, person.NewColName)
	e := echo.New()
	// Define the API route
	e.POST("/createDocument", createDocument)
	input := st.ServerReceive{}
	input.UsernameString = person.Username
	input.PasswordByte = util.EncryptAES(person.Password, dannyUser.AesKey)
	input.ColPath = util.EncryptAES(person.NewColFileId, dannyUser.AesKey)
	input.Payload = util.EncryptAES(st.Marshal(person.Payload), dannyUser.AesKey)
	resp := makeHttpRequestReturnResponse(t, e, input, "POST", "/createDocument")
	if resp.Status == "200" {
		collection := st.Collection{}
		st.Unmarshal(util.ReadFile("collection", person.NewColFileId, true), &collection)
		if _, exists := collection.DocList[person.NewDocumentId]; exists {
			person.Payload["DocId"] = person.NewDocumentId //add manually for testing.
			var raw map[string]interface{}
			st.Unmarshal(util.DecryptAES(dannyUser.AesKey, resp.Data), &raw)
			test_util.TestJSONEquality(person.Payload, raw)
		} else {
			t.Errorf("expected %s to be the new Document ID TestCreateDocument", person.NewDocumentId)
		}
	} else {
		t.Errorf("unexpected status: got %s, want %s TestCreateCollection", resp.Status, "200")
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
	util.DeleteFile("user", person.ExpectedUid, true)
	util.DeleteFile("index", person.NewIndexFileId, true)
	util.DeleteFile("collection", person.NewColFileId, true)
	util.RemoveLineFromFile(util.FindFolder("admin-user"), person.Username+","+person.ExpectedUid)
}

func TestReadDocument(t *testing.T) {
	payload := map[string]interface{}{
		"key1": 42,
		"key2": "value",
		"key3": []int{1, 2, 3},
		"key4": map[string]interface{}{
			"nested1": "nested value",
			"nested2": 3.14,
		},
	}
	person := st.TestData{
		Username:       "danny",
		Password:       "12345",
		ExpectedUid:    "3",
		NewIndexName:   "FirstIndexFakeUser",
		NewIndexFileId: "3-0",
		NewColName:     "FirstCollectionYey",
		NewColFileId:   "3-0-0",
		Payload:        payload,
		NewDocumentId:  "3-0-0-0",
	}
	test_util.Register_testutil(person.Username, person.Password)
	dannyUser, _ := test_util.SignIn_testutil(person.Username, person.Password)
	test_util.CreateIndex_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewIndexName)
	test_util.CreateCollection_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewIndexName, person.NewColName)
	test_util.CreateDocument_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewColFileId, person.Payload)
	e := echo.New()
	// Define the API route
	e.GET("/readDocument", readDocument)
	input := st.ServerReceive{}
	input.UsernameString = person.Username
	input.PasswordByte = util.EncryptAES(person.Password, dannyUser.AesKey)
	input.ColPath = util.EncryptAES(person.NewColFileId, dannyUser.AesKey)
	input.DocumentIdByte = util.EncryptAES(person.NewDocumentId, dannyUser.AesKey)
	resp := makeHttpRequestReturnResponse(t, e, input, "GET", "/readDocument")
	if resp.Status == "200" {
		person.Payload["DocId"] = person.NewDocumentId //add manually for testing.
		var raw map[string]interface{}
		st.Unmarshal(util.DecryptAES(dannyUser.AesKey, resp.Data), &raw)
		test_util.TestJSONEquality(person.Payload, raw)
	} else {
		t.Errorf("unexpected status: got %s, want %s TestReadDocument", resp.Status, "200")
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
	util.DeleteFile("user", person.ExpectedUid, true)
	util.DeleteFile("index", person.NewIndexFileId, true)
	util.DeleteFile("collection", person.NewColFileId, true)
	util.RemoveLineFromFile(util.FindFolder("admin-user"), person.Username+","+person.ExpectedUid)
}

func makeHttpRequestReturnResponse(t *testing.T, e *echo.Echo, input st.ServerReceive, requestType, endpoint string) st.Response {
	req := httptest.NewRequest(requestType, endpoint, bytes.NewReader(st.Marshal(input)))
	req.Header.Set("Content-Type", "application/json")
	// Create a new recorder to capture the response
	rec := httptest.NewRecorder()
	// Call the API handler function, passing in the request and response recorder
	e.ServeHTTP(rec, req)
	// Check the response status code
	if rec.Code != http.StatusOK && rec.Code != http.StatusBadRequest {
		t.Errorf("unexpected status code: got %v, want %v or %v", rec.Code, http.StatusOK, http.StatusBadRequest)
	}
	var resp st.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Errorf("unable to parse response body: %v", err)
	}
	return resp
}

func TestUpdateDocument(t *testing.T) {
	payload := map[string]interface{}{
		"key1": 42,
		"key2": "value",
		"key3": []int{1, 2, 3},
		"key4": map[string]interface{}{
			"nested1": "nested value",
			"nested2": 3.14,
		},
	}
	person := st.TestData{
		Username:       "danny",
		Password:       "12345",
		ExpectedUid:    "3",
		NewIndexName:   "FirstIndexFakeUser",
		NewIndexFileId: "3-0",
		NewColName:     "FirstCollectionYey",
		NewColFileId:   "3-0-0",
		Payload:        payload,
		NewDocumentId:  "3-0-0-0",
	}
	test_util.Register_testutil(person.Username, person.Password)
	dannyUser, _ := test_util.SignIn_testutil(person.Username, person.Password)
	test_util.CreateIndex_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewIndexName)
	test_util.CreateCollection_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewIndexName, person.NewColName)
	test_util.CreateDocument_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewColFileId, person.Payload)
	payload["key1"] = 6969
	payload["DocId"] = person.NewDocumentId
	person.Payload = payload
	e := echo.New()
	// Define the API route
	e.PUT("/updateDocument", updateDocument)
	input := st.ServerReceive{}
	input.UsernameString = person.Username
	input.PasswordByte = util.EncryptAES(person.Password, dannyUser.AesKey)
	input.ColPath = util.EncryptAES(person.NewColFileId, dannyUser.AesKey)
	input.Payload = util.EncryptAES(st.Marshal(person.Payload), dannyUser.AesKey)
	resp := makeHttpRequestReturnResponse(t, e, input, "PUT", "/updateDocument")
	if resp.Status == "200" {
		var raw map[string]interface{}
		st.Unmarshal(util.DecryptAES(dannyUser.AesKey, resp.Data), &raw)
		test_util.TestJSONEquality(person.Payload, raw)
		collection := st.Collection{}
		st.Unmarshal(util.ReadFile("collection", person.NewColFileId, true), &collection)
		if _,exists := collection.DocList[person.NewDocumentId]; exists {
			test_util.TestJSONEquality(person.Payload, collection.DocList[person.NewDocumentId].Data)
		}else{
			t.Errorf("expected %s but not found in DocList TestReadDocument", person.NewDocumentId)
		}
	} else {
		t.Errorf("unexpected status: got %s, want %s TestReadDocument", resp.Status, "200")
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
	util.DeleteFile("user", person.ExpectedUid, true)
	util.DeleteFile("index", person.NewIndexFileId, true)
	util.DeleteFile("collection", person.NewColFileId, true)
	util.RemoveLineFromFile(util.FindFolder("admin-user"), person.Username+","+person.ExpectedUid)
}

func TestDeleteDocument(t *testing.T) {
	payload := map[string]interface{}{
		"key1": 42,
		"key2": "value",
		"key3": []int{1, 2, 3},
		"key4": map[string]interface{}{
			"nested1": "nested value",
			"nested2": 3.14,
		},
	}
	person := st.TestData{
		Username:       "danny",
		Password:       "12345",
		ExpectedUid:    "3",
		NewIndexName:   "FirstIndexFakeUser",
		NewIndexFileId: "3-0",
		NewColName:     "FirstCollectionYey",
		NewColFileId:   "3-0-0",
		Payload:        payload,
		NewDocumentId:  "3-0-0-0",
	}
	test_util.Register_testutil(person.Username, person.Password)
	dannyUser, _ := test_util.SignIn_testutil(person.Username, person.Password)
	test_util.CreateIndex_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewIndexName)
	test_util.CreateCollection_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewIndexName, person.NewColName)
	test_util.CreateDocument_testutil(dannyUser.AesKey, person.Username, person.Password, person.NewColFileId, person.Payload)
	e := echo.New()
	// Define the API route
	e.DELETE("/deleteDocument", deleteDocument)
	input := st.ServerReceive{}
	input.UsernameString = person.Username
	input.PasswordByte = util.EncryptAES(person.Password, dannyUser.AesKey)
	input.ColPath = util.EncryptAES(person.NewColFileId, dannyUser.AesKey)
	input.DocumentIdByte = util.EncryptAES(person.NewDocumentId, dannyUser.AesKey)
	resp := makeHttpRequestReturnResponse(t, e, input, "DELETE", "/deleteDocument")
	if resp.Status == "200" {
		person.Payload["DocId"] = person.NewDocumentId
		var raw map[string]interface{}
		st.Unmarshal(util.DecryptAES(dannyUser.AesKey, resp.Data), &raw)
		test_util.TestJSONEquality(person.Payload, raw)
		collection := st.Collection{}
		st.Unmarshal(util.ReadFile("collection", person.NewColFileId, true), &collection)
		if _, exists := collection.DocList[person.NewDocumentId]; exists {
			t.Errorf("expected %s to be deleted but its not TestReadDocument", person.NewDocumentId)
		}
	} else {
		t.Errorf("unexpected status: got %s, want %s TestReadDocument", resp.Status, "200")
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
	util.DeleteFile("user", person.ExpectedUid, true)
	util.DeleteFile("index", person.NewIndexFileId, true)
	util.DeleteFile("collection", person.NewColFileId, true)
	util.RemoveLineFromFile(util.FindFolder("admin-user"), person.Username+","+person.ExpectedUid)
}
