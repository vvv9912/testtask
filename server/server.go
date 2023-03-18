package server

import (
	"context"
	"google.golang.org/grpc"
	"log"
	"net"
	"testtask/proto"
)

// GRPCServer ...
type GRPCServer struct {
	proto.UnimplementedNetVulnServiceServer
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
	//addr := ":8080" //todo передавать
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

func (s *GRPCServer) CheckVuln(ctx context.Context, request *proto.CheckVulnRequest) *proto.CheckVulnResponse {
	//todo Описать лоигку с nmap
	return &proto.CheckVulnResponse{Results: nil}
}
