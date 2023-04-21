package nondocuments

import (
	util "NoSequel/utils"
	"os"
	"strings"
	"testing"
)

func TestRegisterUser(t *testing.T){
    RegisterUser("ali","1234")
	file, err := os.ReadFile("/Users/zac/Desktop/NoSequel-Database/database/user/0")
	if err != nil {
		t.Errorf(err.Error())
	}
	results := strings.Split(string(file), "\n")
	if results[0] != "ali"{
		t.Errorf("Expected ali, got " + results[0])
	}
	util.DeleteFile("/Users/zac/Desktop/NoSequel-Database/database/user/0")
}