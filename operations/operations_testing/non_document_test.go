package operations_testing

import (
	op "NoSequel/operations"
	st "NoSequel/structures"
	util "NoSequel/utils"
	"errors"
	"os"
	"testing"
)

func testRegisterUser(username, password, expectedUid string) (string, error) {
	Register_testutil(username, password)
	uid := op.ReturnUidFromUsername(username)
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

func testSignIn(username, password, expectedUid string) error {
	user, err := SignIn_testutil(username, password)
	if err != nil {
		return errors.New("Test sign in failed")
	}
	if user.Id != expectedUid {
		return errors.New("Expected UID doesn't match")
	}
	return nil
}

func testCreateIndex(aes []byte, username, password, indexname string) error {
	return CreateIndex_testutil(aes, username, password, indexname)
}

func testCreateCollection(aes []byte, username, password, indexname, colname string) error {
	return CreateCollection_testutil(aes, username, password, indexname, colname)
}

func TestCreateCollection(t *testing.T) {
	person := st.TestData{
		Username:    "danny",
		Password:    "12345",
		ExpectedUid: "3",
	}
	_, e := testRegisterUser(person.Username, person.Password, person.ExpectedUid)
	LogError(e, t)
	e = testSignIn(person.Username, person.Password, person.ExpectedUid)
	LogError(e, t)
	user, _ := SignIn_testutil(person.Username, person.Password)
	person.Aes = user.AesKey
	e = testCreateIndex(person.Aes, person.Username, person.Password, "MyFirstIndex")
	LogError(e, t)
	e = testCreateIndex(person.Aes, person.Username, person.Password, "MySecondIndex")
	LogError(e, t)
	e = testCreateCollection(person.Aes, person.Username, person.Password, "MyFirstIndex", "MyFirstCol")
	LogError(e, t)
	e = testCreateCollection(person.Aes, person.Username, person.Password, "MyFirstIndex", "MySecondCol")
	LogError(e, t)
	os.Remove("desktopPublic.pem")
	os.Remove("desktopPrivate.pem")
	util.DeleteFile("user", person.ExpectedUid, true)
	util.DeleteFile("index", person.ExpectedUid+"-0", true)
	util.DeleteFile("index", person.ExpectedUid+"-1", true)
	util.DeleteFile("collection", person.ExpectedUid+"-0-0", true)
	util.DeleteFile("collection", person.ExpectedUid+"-0-1", true)
	util.RemoveLineFromFile(util.FindFolder("admin-user"), person.Username+","+person.ExpectedUid)
}

func TestGetMetaData(t *testing.T) {
	person := st.TestData{
		Username: "alice",
		Password: "12345",
	}
	e := GetMetaData_testutil(person.Username, person.Password)
	LogError(e, t)
}
