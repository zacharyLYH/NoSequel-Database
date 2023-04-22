package utils

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
	"strings"
)

func Pwd() string{
	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}
	return path
}

/* 
If class is either user/index/collection. Its used to return the path to the intended folder. 
If the class is NOT user/index/collection, just return the root of the project. 
*/
func FindFolder(class string) string{
	folderPath := Pwd()
	position := strings.LastIndex(folderPath, "NoSequel-Database")
	if class == "user" || class == "index" || class == "collection"{
		return folderPath[:position]+"NoSequel-Database/database/"+class
	}else if class == "admin-user" {
		return folderPath[:position]+"NoSequel-Database/database/admin-user"
	}else{
		return folderPath[:position]+"NoSequel-Database/"
	}
}

func CreateTxtFile(folder, fileName string) string{
	myfile, e := os.Create(folder+"/"+fileName)
    if e != nil {
        log.Fatal(e)
    }
    myfile.Close()
	return folder+"/"+fileName
}

func CreateJsonFile(class, fileName string) string {
	myfile, e := os.Create(AssembleFileName(class, fileName, true))
    if e != nil {
        log.Fatal(e)
    }
    myfile.Close()
	return myfile.Name()
}

func AssembleFileName(class, filename string, json bool) string{
	filePath := FindFolder(class)+"/"+filename
	if json {
		filePath += ".json"
	}
	return filePath
}

func ReadFile(class, filename string, json bool) []byte{
	filePath := AssembleFileName(class, filename, json)
	file, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}
	return file
}

func WriteTxtFile(data, filePath string) {
	file,err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
		log.Println("Could not open " + filePath)
		return
	}
	defer file.Close()
  	_, err2 := file.WriteString(data)
	if err2 != nil {
		log.Println("Could not write text to " + filePath)
	}
}

func WriteJsonFile(data []byte, filePath string) {
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func DeleteFile(class, filename string, json bool){
	filePath := AssembleFileName(class, filename, true)
	e := os.Remove(filePath)
    if e != nil {
        log.Fatal(e)
    }
}

/*
RemoveLineFromFile removes the first line that matches the specified text from the specified file.	
The function reads the file into memory, removes the matching line, and writes the updated contents	
back to the file.
*/
func RemoveLineFromFile(filePath string, textToRemove string) error {
    // Open the file for reading and writing.
    file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
    if err != nil {
        return err
    }
    defer file.Close()
    // Create a new scanner to read the file line by line.
    scanner := bufio.NewScanner(file)
    // Create a buffer to hold the new contents of the file.
    var buffer bytes.Buffer
    // Loop through each line in the file.
    for scanner.Scan() {
        line := scanner.Text()
        // If the line does not match the specified text to remove, add it to the buffer.
        if line != textToRemove {
            buffer.WriteString(line)
            buffer.WriteString("\n")
        }
    }
    // Truncate the file to 0 bytes.
    err = file.Truncate(0)
    if err != nil {
        return err
    }
    // Seek to the beginning of the file.
    _, err = file.Seek(0, 0)
    if err != nil {
        return err
    }
    // Write the new contents of the file to the buffer.
    _, err = io.Copy(file, &buffer)
    if err != nil {
        return err
    }
    // Sync the file to ensure that all changes are written to disk.
    err = file.Sync()
    if err != nil {
        return err
    }
    return nil
}

/*
Takes some parameters, and returns the path to the file we're interested in.
This function is meant to be a convenience API. This DB will rely heavily on knowing which file we want to store data into. Its likely generating the file path we're interested in will be a source of bugs because of its ubiquity and criticality, which motivates why we'll invest extra time into this function. 
*/
// func ReturnFilePath(databaseFolder, )