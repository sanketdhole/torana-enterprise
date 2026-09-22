package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	pluginv1 "github.com/phaselume/torana/api/proto/plugin/v1"
	"google.golang.org/grpc"
)

type egressPluginServer struct {
	pluginv1.UnimplementedPluginServiceServer
}

func (s *egressPluginServer) Handshake(_ context.Context, req *pluginv1.HandshakeRequest) (*pluginv1.HandshakeResponse, error) {
	return &pluginv1.HandshakeResponse{
		Accepted: true,
	}, nil
}

func (s *egressPluginServer) Describe(_ context.Context, _ *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	return &pluginv1.DescribeResponse{
		Name:           "egress-mock-connector",
		Version:        "1.0.0",
		Phase:          pluginv1.Phase_PHASE_REQUEST_BODY,
		BodyMode:       pluginv1.BodyMode_BODY_MODE_BUFFERED,
		MaxBufferBytes: 1024 * 1024,
	}, nil
}

func (s *egressPluginServer) OnRequest(_ context.Context, env *pluginv1.Envelope) (*pluginv1.Decision, error) {
	responseBody := fmt.Sprintf(`{"status":"egress_ok","route_id":%q,"received_bytes":%d}`, env.RouteId, len(env.Body))

	return &pluginv1.Decision{
		Action:     pluginv1.Action_ACTION_CONTINUE,
		StatusCode: 200,
		MutateHeaders: map[string]string{
			"X-Egress-Connector": "torana-egress-mock/1.0",
			"Content-Type":       "application/json",
		},
		MutateBody: []byte(responseBody),
	}, nil
}

func main() {
	socketFlag := flag.String("socket", "", "Unix domain socket path")
	tcpFlag := flag.String("tcp", "", "TCP listen address for remote tier")
	flag.Parse()

	socketPath := *socketFlag
	if socketPath == "" {
		socketPath = os.Getenv("TORANA_PLUGIN_SOCKET")
	}

	var listener net.Listener
	var err error

	if *tcpFlag != "" {
		listener, err = net.Listen("tcp", *tcpFlag)
		if err != nil {
			log.Fatalf("failed to listen on tcp %s: %v", *tcpFlag, err)
		}
		log.Printf("egress connector listening on tcp %s", *tcpFlag)
	} else if socketPath != "" {
		_ = os.Remove(socketPath)
		listener, err = net.Listen("unix", socketPath)
		if err != nil {
			log.Fatalf("failed to listen on unix socket %s: %v", socketPath, err)
		}
		defer os.Remove(socketPath)
		log.Printf("egress connector listening on unix socket %s", socketPath)
	} else {
		log.Fatal("neither TORANA_PLUGIN_SOCKET nor --tcp specified")
	}

	server := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(server, &egressPluginServer{})

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		server.GracefulStop()
	}()

	if err := server.Serve(listener); err != nil {
		log.Fatalf("grpc serve failed: %v", err)
	}
}
