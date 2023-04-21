package utils

import (
	"log"
	"os"
)

func CreateFile(folder, fileName string){
	myfile, e := os.Create(folder+"/"+fileName)
    if e != nil {
        log.Fatal(e)
    }
    myfile.Close()
}

func WriteFile(data, filePath string) {
	file,err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
		log.Println("Could not open example.txt")
		return
	}
	defer file.Close()
  	_, err2 := file.WriteString(data)
	if err2 != nil {
		log.Println("Could not write text to example.txt")
	}else{
		log.Println("Operation successful! Text has been appended to example.txt")
  	}
}

func DeleteFile(filePath string){
	e := os.Remove(filePath)
    if e != nil {
        log.Fatal(e)
    }
}

/*
Takes some parameters, and returns the path to the file we're interested in.
This function is meant to be a convenience API. This DB will rely heavily on knowing which file we want to store data into. Its likely generating the file path we're interested in will be a source of bugs because of its ubiquity and criticality, which motivates why we'll invest extra time into this function. 
*/
// func ReturnFilePath(databaseFolder, )