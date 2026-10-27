package sender

import (
	"bufio"
	"fmt"
	"ipspect/internal/analyzer"
	"ipspect/internal/database/load/requests"
	"net"
	"testing"
	"time"
)

func TestProbeRawRunsSequentialExchanges(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverErr := make(chan error, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		_ = conn.SetDeadline(time.Now().Add(time.Second))
		reader := bufio.NewReader(conn)

		first, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if first != "hello\n" {
			serverErr <- fmt.Errorf("unexpected first payload %q", first)
			return
		}

		if _, err = conn.Write([]byte("challenge\n")); err != nil {
			serverErr <- err
			return
		}

		second, err := reader.ReadString('\n')
		if err != nil {
			serverErr <- err
			return
		}
		if second != "answer\n" {
			serverErr <- fmt.Errorf("unexpected second payload %q", second)
			return
		}

		_, err = conn.Write([]byte("accepted\n"))
		serverErr <- err
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	response := ProbeRaw("127.0.0.1", port, analyzer.Probe{
		Exchanges: []requests.Exchange{
			{Payload: []byte("hello\n"), ReadSize: 64},
			{Payload: []byte("answer\n"), ReadSize: 64},
		},
	})

	if string(response) != "challenge\naccepted\n" {
		t.Fatalf("got response %q", response)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}
