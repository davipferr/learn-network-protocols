package demos

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/davipferr/learn-network-protocols/internal/demo"
	"github.com/davipferr/learn-network-protocols/internal/events"
	"github.com/davipferr/learn-network-protocols/internal/h2"
	"github.com/davipferr/learn-network-protocols/internal/pb/learnv1"
	"github.com/davipferr/learn-network-protocols/internal/wire"
)

func init() {
	demo.Register(&demo.Demo{
		ID:      "grpc",
		Title:   "gRPC over HTTP/2",
		Order:   8,
		Group:   "Infrastructure",
		Summary: "A Greeter service defined in a .proto file. The raw HTTP/2 frames are tapped and decoded: SETTINGS, HPACK headers, DATA with protobuf, trailers with grpc-status.",
		Actors:  []string{"client", "server"},
		Lesson: []string{
			"gRPC = a contract in a .proto file + generated code + HTTP/2 transport + protobuf encoding.",
			"Each call is an HTTP/2 stream (1, 3, 5...); many calls share one TCP connection at the same time.",
			"A call is a POST to /package.Service/Method with HEADERS, then DATA frames with length-prefixed protobuf messages.",
			"The result travels in trailers: grpc-status and grpc-message, sent after the data.",
			"HPACK compresses headers using a table shared by both ends: repeated headers shrink to a byte or two.",
			"Protobuf is compact: field numbers and types, not field names, go on the wire.",
		},
		Params: []demo.Param{
			{Name: "name", Default: "Gopher", Help: "name sent to SayHello"},
			{Name: "countdown", Default: "3", Help: "how many messages the server streams back"},
		},
		Run: runGRPC,
	})
}

// greeterServer implements the service defined in proto/learn/v1/greeter.proto.
type greeterServer struct {
	learnv1.UnimplementedGreeterServer
}

func (greeterServer) SayHello(ctx context.Context, req *learnv1.HelloRequest) (*learnv1.HelloReply, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name must not be empty")
	}
	msg := "Hello, " + req.GetName() + "!"
	if req.GetTimes() > 1 {
		msg = strings.TrimSpace(strings.Repeat(msg+" ", int(min(req.GetTimes(), 5))))
	}
	return &learnv1.HelloReply{Message: msg}, nil
}

func (greeterServer) CountDown(req *learnv1.CountDownRequest, stream grpc.ServerStreamingServer[learnv1.Tick]) error {
	for i := min(req.GetFrom(), 20); i > 0; i-- {
		if err := stream.Send(&learnv1.Tick{Value: i, Label: fmt.Sprintf("T-%d", i)}); err != nil {
			return err
		}
		time.Sleep(60 * time.Millisecond)
	}
	return stream.Send(&learnv1.Tick{Value: 0, Label: "liftoff"})
}

func runGRPC(ctx context.Context, em *events.Emitter, p demo.Params) error {
	em.Step("1. The contract", "proto/learn/v1/greeter.proto declares:\n"+
		"  service Greeter {\n"+
		"    rpc SayHello(HelloRequest) returns (HelloReply);       // unary\n"+
		"    rpc CountDown(CountDownRequest) returns (stream Tick); // server streaming\n"+
		"  }\n"+
		"  message HelloRequest { string name = 1; int32 times = 2; }\n"+
		"`buf generate` turned it into Go structs, a client stub and a server interface (internal/pb/learnv1). The server below only implements two methods.")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	// Tap the server side of the TCP connection and decode HTTP/2 frames.
	tapped := wire.NewListener(ln, func(net.Conn) wire.Tap {
		in := h2.NewParser(true)   // client -> server, starts with the preface
		out := h2.NewParser(false) // server -> client
		in.OnPreface = func(raw []byte) {
			em.Send("client", "server", "http2", "connection preface", raw, []events.Field{{Name: "preface", Start: 0, End: len(raw), Value: "PRI * HTTP/2.0 SM"}},
				"A fixed 24-byte string. A server that doesn't speak HTTP/2 will choke on it, so both sides know where they stand immediately.")
		}
		in.OnFrame = func(f h2.Frame) { em.Send("client", "server", "http2", f.Title, f.Raw, f.Fields, f.Detail) }
		out.OnFrame = func(f h2.Frame) { em.Send("server", "client", "http2", f.Title, f.Raw, f.Fields, f.Detail) }
		return func(dir wire.Dir, b []byte) {
			if dir == wire.In {
				in.Feed(b)
			} else {
				out.Feed(b)
			}
		}
	})
	srv := grpc.NewServer()
	learnv1.RegisterGreeterServer(srv, greeterServer{})
	go srv.Serve(tapped)
	defer srv.Stop()
	em.State("server", "gRPC server on "+ln.Addr().String(), "Plaintext HTTP/2 (\"h2c\") so we can read the frames. In production you would add TLS with credentials.NewTLS.")

	em.Step("2. Connecting", "grpc.NewClient is lazy: the TCP connection and the HTTP/2 setup (preface + SETTINGS exchange) happen on the first call.")
	cc, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer cc.Close()
	client := learnv1.NewGreeterClient(cc)
	pause := func() { time.Sleep(60 * time.Millisecond) } // keep frames grouped under their step

	em.Step("3. A unary call: SayHello", "One HEADERS frame (POST /learn.v1.Greeter/SayHello, content-type: application/grpc), one DATA frame with the request, then the response: HEADERS, DATA, and trailers with grpc-status: 0.")
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reply, err := client.SayHello(cctx, &learnv1.HelloRequest{Name: p.String("name"), Times: 1})
	if err != nil {
		return err
	}
	pause()
	em.Info("client", fmt.Sprintf("SayHello returned %q", reply.GetMessage()), "To the program it looks like a local function call.")

	em.Step("4. The same call again: HPACK at work", "Stream 3 this time (client streams use odd numbers). The headers repeat, so HPACK sends small indexes into the shared dynamic table instead of the strings: compare the HEADERS frame sizes with the first call.")
	reply, err = client.SayHello(cctx, &learnv1.HelloRequest{Name: p.String("name"), Times: 2})
	if err != nil {
		return err
	}
	pause()
	em.Info("client", fmt.Sprintf("SayHello returned %q", reply.GetMessage()), "")

	em.Step("5. Server streaming: CountDown", "One request, then several DATA frames on the same stream, one per message, and finally the trailers. The client receives each message as soon as it arrives.")
	stream, err := client.CountDown(cctx, &learnv1.CountDownRequest{From: int32(max(1, p.Int("countdown")))})
	if err != nil {
		return err
	}
	for {
		tick, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		em.Info("client", fmt.Sprintf("stream.Recv() -> value=%d label=%q", tick.GetValue(), tick.GetLabel()), "")
	}
	pause()

	em.Step("6. An error", "Errors are not HTTP status codes: the HTTP status stays 200 and the gRPC status travels in the trailers (grpc-status: 3 = InvalidArgument, grpc-message).")
	_, err = client.SayHello(cctx, &learnv1.HelloRequest{Name: ""})
	pause()
	if st, ok := status.FromError(err); ok && err != nil {
		em.Info("client", fmt.Sprintf("error: code=%s message=%q", st.Code(), st.Message()), "")
	}
	return nil
}
