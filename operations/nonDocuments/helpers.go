package nondocuments

import (
	st "NoSequel/structures"
	util "NoSequel/utils"
	"bufio"
	"bytes"
	"io"
	"log"
	"os"
	"strings"
)

/*
LineCounter counts the number of lines in an io.Reader.
It reads the data from the reader in 32 KB chunks, counts the number of
newline characters, and returns the total count of newlines (i.e. lines).
If an error occurs while reading the data, the function returns the current
count of lines and the error.
*/
func LineCounter(r io.Reader) (int, error) {
	// Initialize a buffer to hold the data read from the reader.
	buf := make([]byte, 32*1024)
	// Initialize a counter to keep track of the number of lines.
	count := 0
	// Define a byte slice that represents the line separator (i.e. newline character).
	lineSep := []byte{'\n'}
	// Loop until the end of the reader is reached or an error occurs.
	for {
		// Read up to 32 KB of data from the reader into the buffer.
		c, err := r.Read(buf)
		// Increment the counter by the number of newline characters in the buffer.
		count += bytes.Count(buf[:c], lineSep)
		// If an error occurred while reading the data...
		if err != nil {
			// If the error was an EOF (i.e. end of file) error, return the final count of lines.
			if err == io.EOF {
				return count, nil
			}
			// Otherwise, return the current count of lines and the error.
			return count, err
		}
	}
}

/*
ReturnUidFromUsername reads the contents of the "admin-user" file and searches for the
line that contains the specified username. If a line containing the username is found,
the function returns the UID (user ID) associated with that username. If no matching line
is found, the function returns an empty string.
The "admin-user" file should have one line per user, with the format "username,uid".
*/
func ReturnUidFromUsername(username string) string {
	// Open the "admin-user" file for reading.
	readFile, err := os.Open(util.FindFolder("admin-user"))
	if err != nil {
		log.Fatal(err)
	}
	defer readFile.Close()
	// Create a new scanner to read the file line by line.
	fileScanner := bufio.NewScanner(readFile)
	fileScanner.Split(bufio.ScanLines)
	// Loop through each line in the file.
	for fileScanner.Scan() {
		// Split the line into separate fields based on the comma separator.
		line := strings.SplitN(fileScanner.Text(), ",", 2)
		// If the first field (i.e. the username) matches the specified username...
		if line[0] == username {
			// Return the UID (i.e. the second field) associated with the username.
			return line[1]
		}
	}
	// If no matching line was found, return an empty string.
	return ""
}

/*
ComparePassword reads the hashed password for the user with the specified UID from the "user" folder
and compares it to the supplied password. If the passwords match, the function returns true. Otherwise,
it returns false.
*/
func ComparePassword(uid string, suppliedPassword []byte) bool {
	// Read the data for the user with the specified UID from the "user" folder.
	data := util.ReadFile("user", uid, true)
	// Unmarshal the data into a User struct.
	user := st.User{}
	st.Unmarshal(data, &user)
	// Compare the hashed password for the user to the supplied password.
	// Note: The user's password is stored as a byte slice that has been hashed using a secure hashing algorithm.
	// To compare the passwords, we use the bytes.Equal function from the standard library.
	return bytes.Equal(user.Password, suppliedPassword)
}

// GetAesKeyFromUsername retrieves the AES key for a given username.
func GetAesKeyFromUsername(username string) []byte {
	// Obtain the user ID associated with the provided username
	uid := ReturnUidFromUsername(username)
	// Read user data only once and unmarshal it
	userData := st.User{}
	userDataBytes := util.ReadFile("user", uid, true)
	st.Unmarshal(userDataBytes, &userData)
	return userData.AesKey
}

// GetPasswordFromUsername retrieves the password for a given username.
func GetPasswordFromUsername(username string) []byte {
	// Obtain the user ID associated with the provided username
	uid := ReturnUidFromUsername(username)
	// Read user data only once and unmarshal it
	userData := st.User{}
	userDataBytes := util.ReadFile("user", uid, true)
	st.Unmarshal(userDataBytes, &userData)
	return userData.Password
}

/*
Takes a username and password. Returns true if the user's credentials match up, otherwise return false
*/
func CheckCredentials(username string, password []byte) bool {
	aes := GetAesKeyFromUsername(username)
	// Decrypt the password and check
	return bytes.Equal(GetPasswordFromUsername(username), []byte(util.DecryptAES(aes, password)))
}

// CreateIndexFile creates a new index file for the specified user and index.
// It returns the file name of the created index file.
func CreateIndexFile(uid, iid, username, indexname string) string {
	// Assemble file name using uid and iid
	fileName := uid + "-" + iid
	// Create the JSON file for the index
	util.CreateJsonFile("index", fileName)
	// Initialize index data
	data := st.Index{
		Owner:          username,
		Id:             iid,
		IndexName:      indexname,
		CollectionSet: make(map[string]struct{}),
	}
	// Write index data to the file
	util.WriteJsonFile(st.Marshal(data), util.AssembleFileName("index", fileName, true))
	return fileName
}

// This function and the above function can be modularized.
func CreateCollectionFile(uid, iid, cid, colname, indexname string) string {
	// Assemble file name using uid and iid and cid
	fileName := uid + "-" + iid + "-" + cid
	// Create the JSON file for the collection
	util.CreateJsonFile("collection", fileName)
	col := st.Collection{
		Index:   indexname,
		ColName: colname,
		DocList: make(map[string]st.Document),
	}
	// Write index data to the file
	util.WriteJsonFile(st.Marshal(col), util.AssembleFileName("collection", fileName, true))
	return fileName
}
