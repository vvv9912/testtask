package main

import (
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"os"
	"testtask/server"
)

func main() {
	type cfg struct {
		Port string `yaml:"port"`
	}
	ucfg := cfg{}
	data, err := os.ReadFile("server/conf.yml")

	if err != nil {
		logrus.WithFields(
			logrus.Fields{
				"package": "main",
				"func":    "main",
				"method":  "ReadFile",
			}).Fatalf("err read config: %v", err)
	}
	err = yaml.Unmarshal([]byte(data), &ucfg)
	if err != nil {
		logrus.WithFields(
			logrus.Fields{
				"package": "main",
				"func":    "main",
				"method":  "Unmarshal",
			}).Fatalf("err unmarshal config: %v", err)
	}
	if ucfg.Port != "" {
		logrus.Infof("port: %v", ucfg.Port)
	} else {
		logrus.WithFields(
			logrus.Fields{
				"package": "main",
				"func":    "main",
			}).Fatal("err config")
	}

	done := make(chan bool)
	ucfg.Port = ":" + ucfg.Port
	err = server.ServerStart(ucfg.Port, done)
	if err != nil {
		logrus.WithFields(
			logrus.Fields{
				"package": "main",
				"func":    "main",
				"method":  "ServerStart",
			}).Fatal(err)
	}
}
