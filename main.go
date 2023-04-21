package main

import (
	utils "NoSequel/utils"
)

func main(){
	// utils.CreateFile("database/user", "u1")
	// utils.WriteFile("hello world", "database/user/u1")
	utils.DeleteFile("database/user/u1")
}