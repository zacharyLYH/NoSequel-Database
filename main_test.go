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
	// Create a new request to the /sayHello endpoint
	req := httptest.NewRequest(http.MethodGet, "/sayHello", nil)
	// Create a new response recorder to capture the response
	rec := httptest.NewRecorder()
	// Call the /sayHello endpoint with the request and response recorder
	e.ServeHTTP(rec, req)
	// Check the response status code
	if rec.Code != http.StatusOK {
		t.Errorf("unexpected status code: got %v, want %v", rec.Code, http.StatusOK)
	}
	// Parse the response body into a Response object
	var resp st.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Errorf("unable to parse response body: %v", err)
	}
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
	payload, _ := json.Marshal(input)
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
	// log.Println(st.Marshal(signInRequestBody))
	req := httptest.NewRequest(http.MethodPost, "/signIn", bytes.NewReader(st.Marshal(input)))
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
	req := httptest.NewRequest(http.MethodGet, "/getMetaData", bytes.NewReader(st.Marshal(input)))
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
	}
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
}
