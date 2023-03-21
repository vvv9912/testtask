package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"testtask/server"
)

func main() {
	addr := ":8080"
	fmt.Println(addr)
	done := make(chan bool, 1)

	err := server.ServerStart(addr, done)
	if err != nil {
		logrus.WithFields(
			logrus.Fields{
				"package": "main",
				"func":    "main",
				"method":  "ServerStart",
			}).Fatal(err)
	}
}
