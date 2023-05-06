package main

import (
	"github.com/labstack/echo"
)

func main() {
	// Create a new instance of the Echo router
	e := echo.New()
	e.GET("/sayHello", sayHello)
	e.POST("/register", register)
	// Start the Echo server on port 8080
	e.Start(":8080")
}
