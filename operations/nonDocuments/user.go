package nondocuments

import (
	utils "NoSequel/utils"
	"os"
	"strconv"
	"strings"
)

/*
username
password
id
indexList []string
*/
func RegisterUser(username, password string){
	databaseUserPath := utils.Pwd()
	position := strings.LastIndex(databaseUserPath, "NoSequel-Database")
	databaseUserPath = databaseUserPath[:position]+"NoSequel-Database/database/user"
	d, e := os.ReadDir(databaseUserPath)
	if e != nil {
		panic(e)
	}
	nextUid := strconv.Itoa(len(d))
	utils.CreateFile(databaseUserPath, nextUid)
	utils.WriteFile(username+"\n"+password+"\n"+nextUid, databaseUserPath+"/"+nextUid)
}