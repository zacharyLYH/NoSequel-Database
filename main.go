package main

import (
	"github.com/labstack/echo"
)

func main() {
	// Create a new instance of the Echo router
	e := echo.New()
	e.GET("/sayHello", sayHello)
	e.POST("/register", register)
	e.GET("/getMetaData", getMetaData)
	e.POST("/signIn", signIn)
	e.POST("/createIndex", createIndex)
	e.POST("/createCollection", createCollection)
	e.POST("/createDocument", createDocument)
	e.GET("/readDocument", readDocument)
	e.PUT("/updateDocument", updateDocument)
	// Start the Echo server on port 8080
	e.Start(":8080")
}
