package main

import (
	"fmt"
	"testtask/server"
)

func main() {
	addr := ":8080"
	fmt.Println(addr)
	err := server.ServerStart(addr)
	if err != nil {
		fmt.Println(err)
	}
}
