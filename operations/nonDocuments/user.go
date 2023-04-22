package nondocuments

import (
	st "NoSequel/structures"
	util "NoSequel/utils"
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
)

func LineCounter(r io.Reader) (int, error) {
    buf := make([]byte, 32*1024)
    count := 0
    lineSep := []byte{'\n'}
    for {
        c, err := r.Read(buf)
        count += bytes.Count(buf[:c], lineSep)

        switch {
        case err == io.EOF:
            return count, nil

        case err != nil:
            return count, err
        }
    }
}
/*
username
password
id
indexList []string
aesKey
*/
func RegisterUser(username, password string) { 
	if ReturnUidFromUsername(username) != ""{
		log.Fatal("Attempting to create duplicate username")
	}
	adminPath := util.AssembleFileName("admin-user", "", false)[:len(util.AssembleFileName("admin-user", "", false))-1] //SUPER INELEGANT
	file, err := os.OpenFile(adminPath, os.O_RDONLY, 0444)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	fileSize, err := LineCounter(file)
	if err != nil{
		log.Fatal(err)
	}
	nextUid := strconv.Itoa(fileSize)
	jsonFilePath := util.CreateJsonFile("user", nextUid)
	log.Println(jsonFilePath)
	user := st.User{
		Username: []byte(username),
		Password: []byte(password),
		Id: nextUid,
	}
	util.WriteJsonFile(st.Marshal(user), jsonFilePath)
	util.WriteTxtFile(username+","+nextUid+"\n", util.FindFolder("admin-user"))
}

func ReturnUidFromUsername(username string) string {
	readFile, err := os.Open(util.FindFolder("admin-user"))
    if err != nil {
        log.Fatal(err)
    }
    fileScanner := bufio.NewScanner(readFile)
    fileScanner.Split(bufio.ScanLines)
    for fileScanner.Scan() {
        line := strings.Split(fileScanner.Text(), ",")
		if line[0] == username{
			return line[1]
		}
    }
    readFile.Close()
	return ""
}

// Supply uid without prefixing "/"
func ComparePassword(uid string, suppliedPassword []byte) bool {
	data := util.ReadFile("user", uid, true)
	user := st.User{}
	st.Unmarshal(data, &user)
	return bytes.Equal(user.Password, suppliedPassword)
}

//Takes an encrypted string of username, password, desktopPublicKey. Only username and password are encrypted - use serverPrivateKey to decrypt this information. Generate an aesKey and append it to the file 
func SignIn(ciphertext []byte) []byte {
	privateKey := util.ExtractPrivKey(util.FindFolder("rsa")+"serverPrivate.pem")
	plaintext := st.User{}
	st.Unmarshal(ciphertext, &plaintext)
	plaintext.Username = util.DecryptRSA(plaintext.Username, privateKey)
	plaintext.Password = util.DecryptRSA(plaintext.Password, privateKey)
	uid := ReturnUidFromUsername(string(plaintext.Username))
	ret := st.User{}
	if ComparePassword(uid, plaintext.Password){ // sign in successful
		data := st.User{}
		st.Unmarshal(util.ReadFile("user", uid, true), &data)
		ret.AesKey = util.GenerateSymKey(32) 
		ret.IndexList = data.IndexList
		ret.Id = data.Id
		ret.Username = data.Username
		saveAes := st.User{} //write the aes key to file
		st.Unmarshal(ciphertext, &saveAes)
		saveAes.AesKey = ret.AesKey
		saveAes.Id = data.Id
		saveAes.ClientPub = nil
		util.WriteJsonFile(st.Marshal(saveAes), util.AssembleFileName("user", uid, true))
	}
	return util.EncryptRSA(plaintext.ClientPub, st.Marshal(ret))//if fail, return an empty struct
}