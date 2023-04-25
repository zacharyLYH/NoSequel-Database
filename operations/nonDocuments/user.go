package nondocuments

import (
	st "NoSequel/structures"
	util "NoSequel/utils"
	"log"
	"os"
	"strconv"
)

/*
RegisterUser checks if the specified username already exists in the "admin-user" file. If the
username is not a duplicate, the function creates a new user ID and saves the user's username,
password, and ID in the "user" and "admin-user" files.
*/
func RegisterUser(username, password string) {
	// Check if the specified username already exists in the "admin-user" file.
	if ReturnUidFromUsername(username) != "" {
		log.Fatal("Attempting to create duplicate username")
	}
	// Get the path to the "admin-user" file and open it for reading.
	adminPath := util.FindFolder("admin-user")
	file, err := os.OpenFile(adminPath, os.O_RDONLY, 0444)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	// Get the current size of the "admin-user" file (i.e. the number of existing users).
	fileSize, err := LineCounter(file)
	if err != nil {
		log.Fatal(err)
	}
	// Generate a new UID (user ID) for the new user by converting the file size to a string.
	nextUid := strconv.Itoa(fileSize)
	// Create a new JSON file for the user's data using the new UID.
	jsonFilePath := util.CreateJsonFile("user", nextUid)
	// Create a new User struct with the username, password, and UID.
	user := st.User{
		Username: []byte(username),
		Password: []byte(password),
		Id:       nextUid,
	}
	// Write the user's data to the JSON file.
	util.WriteJsonFile(st.Marshal(user), jsonFilePath)
	// Append the user's username and UID to the "admin-user" file.
	util.WriteTxtFile(username+","+nextUid+"\n", adminPath)
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
		saveAes.Username = plaintext.Username
		saveAes.Password = plaintext.Password
		saveAes.IndexList = ret.IndexList
		// Write the updated User instance to file
		util.WriteJsonFile(st.Marshal(saveAes), util.AssembleFileName("user", uid, true))
	}
	// Encrypt and return the serialized return User instance
	return util.EncryptRSA(plaintext.ClientPub, st.Marshal(ret))
}

/*
RegisterIndex creates a new index for a user if the provided password is correct.
The index name and password are decrypted using the user's AES key before processing.
The function returns an appropriate response message based on the operation result.
*/
func RegisterIndex(indexname, password []byte, username string) st.Response {
	// Initialize response struct
	response := st.Response{}
	// Get the AES key for the username
	aes := GetAesKeyFromUsername(username)
	// Decrypt indexname using the AES key
	decryptIndexName := util.DecryptAES(aes, indexname)
	// Get the user's unique ID
	uid := ReturnUidFromUsername(username)
	// Read user data only once
	userData := st.User{}
	userDataBytes := util.ReadFile("user", uid, true)
	st.Unmarshal(userDataBytes, &userData)
	// Check for password match before performing other operations
	if !CheckCredentials(username, password) {
		response.Message = []byte("Something went wrong. Might be a bad password")
		response.Status = "403"
		return response
	}
	// Use a boolean flag to check for duplicate indexes
	duplicate := false
	for _, d := range userData.IndexList {
		index := st.Index{}
		st.Unmarshal(util.ReadFile("index", d, true), &index)
		if index.IndexName == decryptIndexName {
			duplicate = true
			break
		}
	}
	// Return an error response if a duplicate index is found
	if duplicate {
		response.Message = []byte("Attempting to create duplicate index")
		response.Status = "400"
		return response
	}
	// Create the new index file and update the user data
	newIndexFileName := CreateIndexFile(uid, strconv.Itoa(len(userData.IndexList)), username, decryptIndexName)
	userData.IndexList = append(userData.IndexList, newIndexFileName)
	util.WriteJsonFile(st.Marshal(userData), util.AssembleFileName("user", uid, true))
	// Return a success response with the created index details
	response.Message = []byte("Successfully created the index " + decryptIndexName + " in the file " + newIndexFileName)
	response.Status = "200"
	return response
}
