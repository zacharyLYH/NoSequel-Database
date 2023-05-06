package main

import (
	nd "NoSequel/operations/nonDocuments"
	st "NoSequel/structures"
	"net/http"

	"github.com/labstack/echo"
)

func deserializeInputJSON(c echo.Context) st.ServerReceive {
	data := st.ServerReceive{}
	if err := c.Bind(&data); err != nil {
		data.DeserializeSuccesful = true
	} else {
		data.DeserializeSuccesful = false
	}
	return data
}

func sayHello(c echo.Context) error {
	resp := st.Response{}
	resp.Status = "200"
	resp.Message = []byte("Hello World")
	return c.JSON(http.StatusOK, resp)
}

func register(c echo.Context) error {
	data := deserializeInputJSON(c)
	resp := nd.RegisterUser(data.Username, data.PasswordString)
	if resp.Status == "200" {
		return c.JSON(http.StatusOK, resp)
	} else {
		return c.JSON(http.StatusBadRequest, resp)
	}
}

func signIn(c echo.Context) error {
	data := deserializeInputJSON(c)
	resp := nd.SignIn(data.Payload)
	if resp.Status == "200" {
		return c.JSON(http.StatusOK, resp)
	} else {
		return c.JSON(http.StatusBadRequest, resp)
	}
}

// func createDocument(c echo.Context) error {
//     return c.JSON(http.StatusOK, "Hello, World!")
// }
