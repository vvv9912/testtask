package server

import (
	"context"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"net"
	"testtask/nmap"
	"testtask/proto"
)

// GRPCServer ...
type GRPCServer struct {
	proto.NetVulnServiceServer
}

// constructor
func NewServer() *GRPCServer {
	return &GRPCServer{}
}

// server start
func ServerStart(addr string, done chan bool) error {
	//создаем сервер
	server := grpc.NewServer()
	//добавляем экстрадер
	srv := NewServer()
	proto.RegisterNetVulnServiceServer(server, srv)
	//
	list, err := net.Listen("tcp", addr)
	if err != nil {
		logrus.WithFields(
			logrus.Fields{
				"package": "server",
				"func":    "ServerStart",
				"method":  "Listen",
			}).Fatal(err)
	}
	go func() {
		err = server.Serve(list)
		if err != nil {
			logrus.WithFields(
				logrus.Fields{
					"package": "server",
					"func":    "ServerStart",
					"method":  "Serve",
				}).Fatal(err)
		}

	}()
	for {
		select {
		case <-done:
			server.Stop()
			return nil
		default:

		}
	}
	//return nil
}

func (s *GRPCServer) CheckVuln(ctx context.Context, request *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	targets := request.GetTargets()
	tcpPorts := request.GetTcpPort()
	targRes, err := nmap.Scanner(targets, tcpPorts)
	if err != nil {
		logrus.WithFields(
			logrus.Fields{
				"package": "server",
				"func":    "CheckVuln",
				"method":  "Scanner",
			}).Fatal(err)
	}

	return &proto.CheckVulnResponse{Results: targRes}, nil
}
