package server

import (
	"context"
	"google.golang.org/grpc"
	"log"
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
func ServerStart(addr string) error {
	//создаем сервер
	server := grpc.NewServer()
	//добавляем экстрадер
	srv := NewServer()
	proto.RegisterNetVulnServiceServer(server, srv)
	//
	list, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	//todo В горутину
	err = server.Serve(list)
	if err != nil {
		log.Fatal(err)
	}
	return nil

}

func (s *GRPCServer) CheckVuln(ctx context.Context, request *proto.CheckVulnRequest) (*proto.CheckVulnResponse, error) {
	targets := request.GetTargets()
	tcpPorts := request.GetTcpPort()
	TargRes, err := nmap.Scanner(targets, tcpPorts)
	if err != nil {
		log.Fatal(err)
	}

	return &proto.CheckVulnResponse{Results: TargRes}, nil
}
