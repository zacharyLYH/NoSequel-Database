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

func RegisterUser(username, password string) { 
	if ReturnUidFromUsername(username) != ""{
		log.Fatal("Attempting to create duplicate username")
	}
	adminPath := util.FindFolder("admin-user")
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
	util.WriteTxtFile(username+","+nextUid+"\n", adminPath)
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

/*
SignIn handles the user sign-in process. The function takes an encrypted 
ciphertext byte slice as input, which contains the user's credentials. It 
decrypts the credentials and validates them. If successful, it returns 
encrypted user data, including the user's ID, username, index list, and a 
newly generated AES key for further communication. If the sign-in process
fails, it returns an empty struct encrypted with the user's public key.
*/
func SignIn(ciphertext []byte) []byte {
	// Extract the server's private key
	privateKey := util.ExtractPrivKey(util.FindFolder("rsa") + "serverPrivate.pem")
	// Deserialize the ciphertext into a plaintext User instance
	plaintext := st.User{}
	st.Unmarshal(ciphertext, &plaintext)
	// Decrypt the user's credentials using the server's private key
	plaintext.Username = util.DecryptRSA(plaintext.Username, privateKey)
	plaintext.Password = util.DecryptRSA(plaintext.Password, privateKey)
	// Obtain the user ID associated with the provided username
	uid := ReturnUidFromUsername(string(plaintext.Username))
	// Initialize a return User instance
	ret := st.User{}
	// Check if the provided password is correct
	if ComparePassword(uid, plaintext.Password) {
		// Deserialize the user's data from the file
		data := st.User{}
		st.Unmarshal(util.ReadFile("user", uid, true), &data)
		// Generate a new AES key for further communication
		ret.AesKey = util.GenerateSymKey(32)
		// Populate the return User instance with the necessary data
		ret.IndexList = data.IndexList
		ret.Id = data.Id
		ret.Username = data.Username
		// Create a new User instance to save the AES key to file
		saveAes := st.User{}
		st.Unmarshal(ciphertext, &saveAes)
		saveAes.AesKey = ret.AesKey
		saveAes.Id = data.Id
		saveAes.ClientPub = nil
		// Write the updated User instance to file
		util.WriteJsonFile(st.Marshal(saveAes), util.AssembleFileName("user", uid, true))
	}
	// Encrypt and return the serialized return User instance
	return util.EncryptRSA(plaintext.ClientPub, st.Marshal(ret)) 
}
