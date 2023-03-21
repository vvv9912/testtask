package server

import (
	"context"
	"fmt"
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
		logrus.Info("server is running")
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
	chanTargRes := make(chan []*proto.TargetResult)
	go func(targets []string, tcpPorts []int32) {
		targRes, err := nmap.Scanner(targets, tcpPorts)
		if err != nil {
			logrus.WithFields(
				logrus.Fields{
					"package": "server",
					"func":    "CheckVuln",
					"method":  "Scanner",
				}).Fatal(err)
			chanTargRes <- nil
		}
		chanTargRes <- targRes
	}(targets, tcpPorts)

	var targres []*proto.TargetResult
	select {
	case <-ctx.Done():
		logrus.WithFields(
			logrus.Fields{
				"package": "server",
				"func":    "CheckVuln",
				"method":  "Scanner",
			}).Info("cancellation of the request")
		return nil, fmt.Errorf("cancellation of the request")
	case targres = <-chanTargRes:

	}

	return &proto.CheckVulnResponse{Results: targres}, nil
}
