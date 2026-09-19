package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/local/reorigin-burnout-paradise/bpserver"
	"github.com/local/reorigin-burnout-paradise/legacytls"
)

func main() {

	directoryAddr := flag.String("directory", "127.0.0.1:21841", "EASO directory listener")
	gameAddr := flag.String("game", "127.0.0.1:21842", "redirected EASO service listener")
	advertiseAddr := flag.String("advertise", "127.0.0.1", "IP returned in the @dir response")
	sessionValue := flag.String("session", "1558760620", "decimal EASO session identifier")
	mask := flag.String("mask", bpserver.DefaultMask, "32-character hexadecimal EASO mask")
	certFile := flag.String("cert", "", "PEM certificate chain (optional; must be used with -key)")
	keyFile := flag.String("key", "", "PEM RSA private key (optional; must be used with -cert)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if (*certFile == "") != (*keyFile == "") {

		logger.Error("-cert and -key must be supplied together")
		os.Exit(2)

	}

	var tlsConfig *legacytls.Config
	var err error

	if *certFile != "" {
		tlsConfig, err = legacytls.LoadKeyPair(*certFile, *keyFile)
	} else {
		tlsConfig, err = bpserver.GenerateDirtySDK64SelfSigned("pcburnout08.ea.com", "localhost")
	}
	if err != nil {
		logger.Error("certificate setup failed", "error", err)
		os.Exit(2)
	}
	if err := bpserver.ValidateDirtySDK64Certificate(tlsConfig); err != nil {
		logger.Error("DirtySDK 6.4 certificate validation failed", "error", err)
		os.Exit(2)
	}

	tlsConfig.Trace = func(event string, attrs ...any) {
		logger.Info("ProtoSSL "+event, attrs...)
	}

	sessionID, err := bpserver.ParseSessionID(*sessionValue)
	if err != nil {
		logger.Error("invalid session", "value", *sessionValue, "error", err)
		os.Exit(2)
	}

	_, gamePortText, err := net.SplitHostPort(*gameAddr)
	if err != nil {
		logger.Error("invalid game listener", "address", *gameAddr, "error", err)
		os.Exit(2)
	}

	gamePort, err := strconv.Atoi(gamePortText)
	if err != nil {
		logger.Error("invalid game port", "port", gamePortText, "error", err)
		os.Exit(2)
	}

	server, err := bpserver.New(bpserver.Config{
		AdvertiseAddress: *advertiseAddr,
		GamePort:         gamePort,
		SessionID:        sessionID,
		Mask:             *mask,
		Logger:           logger,
	})
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(2)
	}

	// Burnout's directory redirect carries an IPv4 ADDR and the retail
	// client opens the follow-up service socket as AF_INET.  Explicitly use
	// tcp4 here so a wildcard address cannot resolve to a v6-only listener on
	// Windows (which would make the directory handshake succeed, then leave
	// the client unable to reach the redirected service).
	directoryTCP, err := net.Listen("tcp4", *directoryAddr)
	if err != nil {
		logger.Error("directory listen failed", "error", err)
		os.Exit(1)
	}
	defer directoryTCP.Close()

	gameTCP, err := net.Listen("tcp4", *gameAddr)
	if err != nil {
		logger.Error("game listen failed", "error", err)
		os.Exit(1)
	}
	defer gameTCP.Close()

	game := gameTCP
	directory := legacytls.NewListener(directoryTCP, tlsConfig)
	// The directory endpoint is SSLv3, but its @dir response redirects the
	// retail client to a plaintext EASO service socket. Wrapping this listener
	// in TLS makes ordinary frame types such as ?tic, skey, news, and addr look
	// like invalid TLS record versions (for example "ke" == 0x6b65).

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info("Burnout Paradise EASO server",
		"build", "2026-09-07-presence-fix",
		"directory", directory.Addr(), "game", game.Addr(), "advertise", *advertiseAddr,
		"directory_transport", "SSL 3.0/TLS 1.0 RSA/RC4",
		"service_transport", "plaintext ?tic then RC4+MD5-V2")

	errCh := make(chan error, 2)
	go func() { errCh <- server.Serve(ctx, directory, "directory") }()
	go func() { errCh <- server.Serve(ctx, game, "service") }()
	if err := <-errCh; err != nil && ctx.Err() == nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}

}
