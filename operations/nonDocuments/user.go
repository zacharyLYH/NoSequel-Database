package nondocuments

import (
	utils "NoSequel/utils"
	"os"
	"strconv"
)

/*
username
password
id
indexList []string
*/
func RegisterUser(username, password string){
	databaseUserPath := utils.FindFolder("user")
	d, e := os.ReadDir(databaseUserPath)
	if e != nil {
		panic(e)
	}
	nextUid := strconv.Itoa(len(d))
	utils.CreateFile(databaseUserPath, nextUid)
	utils.WriteFile(username+"\n"+password+"\n"+nextUid, databaseUserPath+"/"+nextUid)
}