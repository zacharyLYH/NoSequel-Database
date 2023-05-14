package main

import (
	doc "NoSequel/operations/documents"
	nd "NoSequel/operations/nonDocuments"
	st "NoSequel/structures"
	util "NoSequel/utils"
	"log"
	"net/http"

	"github.com/labstack/echo"
)

func deserializeInputJSON(c echo.Context) (st.ServerReceive, error) {
	data := st.ServerReceive{}
	if err := c.Bind(&data); err != nil {
		log.Printf("failed to parse request body: %v", err)
		return st.ServerReceive{}, err
	}
	return data, nil
}

func sayHello(c echo.Context) error {
	resp := st.Response{}
	resp.Status = "200"
	resp.Message = []byte("Hello World")
	return c.JSON(http.StatusOK, resp)
}

func register(c echo.Context) error {
	data, e := deserializeInputJSON(c)
	if e != nil {
		return e
	}
	privateKey := util.ExtractPrivKey(util.FindFolder("rsa") + "serverPrivate.pem")
	decryptedUsername := string(util.DecryptRSA(data.UsernameByte, privateKey))
	decryptedPassword := string(util.DecryptRSA(data.PasswordByte, privateKey))
	resp := nd.RegisterUser(decryptedUsername, decryptedPassword)
	if resp.Status == "200" {
		return c.JSON(http.StatusOK, resp)
	} else {
		return c.JSON(http.StatusBadRequest, resp)
	}
}

func signIn(c echo.Context) error {
	data, e := deserializeInputJSON(c)
	if e != nil {
		return e
	}
	resp := nd.SignIn(data.Payload)
	if resp.Status == "200" {
		return c.JSON(http.StatusOK, resp)
	} else {
		return c.JSON(http.StatusBadRequest, resp)
	}
}

func getMetaData(c echo.Context) error {
	data, e := deserializeInputJSON(c)
	if e != nil {
		return e
	}
	resp := nd.GetMetaData(data.UsernameString, data.PasswordByte)
	if resp.Status == "200" {
		return c.JSON(http.StatusOK, resp)
	} else {
		return c.JSON(http.StatusBadRequest, resp)
	}
}

func createIndex(c echo.Context) error {
	data, e := deserializeInputJSON(c)
	if e != nil {
		return e
	}
	resp := nd.RegisterIndex(data.IndexNameByte, data.PasswordByte, data.UsernameString)
	if resp.Status == "200" {
		return c.JSON(http.StatusOK, resp)
	} else {
		return c.JSON(http.StatusBadRequest, resp)
	}
}

func createCollection(c echo.Context) error {
	data, e := deserializeInputJSON(c)
	if e != nil {
		return e
	}
	resp := nd.RegisterCollection(data.UsernameString, data.IndexNameByte, data.ColNameByte, data.PasswordByte)
	if resp.Status == "200" {
		return c.JSON(http.StatusOK, resp)
	} else {
		return c.JSON(http.StatusBadRequest, resp)
	}
}

func createDocument(c echo.Context) error {
	data, e := deserializeInputJSON(c)
	if e != nil {
		return e
	}
	resp := doc.Create(data.UsernameString, data.PasswordByte, data.ColPath, data.Payload)
	if resp.Status == "200" {
		return c.JSON(http.StatusOK, resp)
	} else {
		return c.JSON(http.StatusBadRequest, resp)
	}
}

func readDocument(c echo.Context) error {
	data, e := deserializeInputJSON(c)
	if e != nil {
		return e
	}
	resp := doc.Read(data.UsernameString, data.PasswordByte, data.ColPath, data.DocumentIdByte)
	if resp.Status == "200" {
		return c.JSON(http.StatusOK, resp)
	} else {
		return c.JSON(http.StatusBadRequest, resp)
	}
}