package bpserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/local/reorigin-burnout-paradise/easo"
	"github.com/local/reorigin-burnout-paradise/legacytls"
)

func TestCapturedPCSSL3ClientHelloIsAccepted(t *testing.T) {
	server, err := New(Config{
		AdvertiseAddress: "127.0.0.1",
		GamePort:         21842,
		SessionID:        1,
		Mask:             DefaultMask,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := legacytls.GenerateSelfSigned("pcburnout08.ea.com")
	if err != nil {
		t.Fatal(err)
	}

	serverNet, clientNet := net.Pipe()
	defer clientNet.Close()
	if err := clientNet.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.handleConnection(ctx, legacytls.Server(serverNet, tlsConfig), "directory")

	// Exact first flight captured from the original PC executable. It is an
	// SSLv3 ClientHello offering RSA/RC4-SHA and RSA/RC4-MD5 only.
	clientHello, err := hex.DecodeString(
		"160300002f0100002b030095dd6534a6b648a8d21aa46cb0cd4e6115aa3e86ad5eec213990a5525c583c21000004000500040100",
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientNet.Write(clientHello); err != nil {
		t.Fatal(err)
	}

	var header [5]byte
	if _, err := io.ReadFull(clientNet, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[0] != 22 || binary.BigEndian.Uint16(header[1:3]) != 0x0300 {
		t.Fatalf("server record header = %x", header)
	}
	flight := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	if _, err := io.ReadFull(clientNet, flight); err != nil {
		t.Fatal(err)
	}
	if len(flight) < 4 || flight[0] != 2 {
		t.Fatalf("first server handshake message = %x", flight)
	}
}

func TestDirectoryHandshake(t *testing.T) {
	server, err := New(Config{
		AdvertiseAddress: "127.0.0.1",
		GamePort:         21842,
		SessionID:        1558760620,
		Mask:             DefaultMask,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.handleConnection(ctx, serverConn, "directory")

	if err := easo.Write(clientConn, easo.Frame{Type: "@tic", Payload: []byte("RC4+MD5-V2\x00")}); err != nil {
		t.Fatal(err)
	}
	tic, err := easo.Read(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if tic.Type != "@tic" || len(tic.Payload) != 84 {
		t.Fatalf("challenge = type %q, payload %d", tic.Type, len(tic.Payload))
	}

	request := []byte("VERS=BURNOUT5/ISLAND\nSKU=PC\nSDKVERS=6.4.0.0\n\x00")
	if err := easo.Write(clientConn, easo.Frame{Type: "@dir", Payload: request}); err != nil {
		t.Fatal(err)
	}
	dir, err := easo.Read(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("ADDR=127.0.0.1\tPORT=21842\tSESS=1558760620\tMASK=" + DefaultMask + "\x00")
	if dir.Type != "@dir" || !bytes.Equal(dir.Payload, want) {
		t.Fatalf("directory response = %q %q", dir.Type, dir.Payload)
	}
	_ = clientConn.Close()
}

func TestServiceTicketEnablesSecureFrames(t *testing.T) {
	server, err := New(Config{
		AdvertiseAddress: "127.0.0.1",
		GamePort:         21842,
		SessionID:        1,
		Mask:             DefaultMask,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	server.keepalivePeriod = 25 * time.Millisecond

	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go server.handleConnection(ctx, serverConn, "service")

	if err := easo.Write(clientConn, easo.Frame{Type: "?tic", Payload: serverChallenge[32:]}); err != nil {
		t.Fatal(err)
	}
	clientSecure, err := easo.NewSecureEASO(clientConn, serverChallenge[16:32], serverChallenge[:16])
	if err != nil {
		t.Fatal(err)
	}
	if err := clientSecure.Write(easo.Frame{Type: "addr", Payload: []byte("ADDR=127.0.0.1\nPORT=12345\n\x00")}); err != nil {
		t.Fatal(err)
	}
	if err := clientSecure.Write(easo.Frame{Type: "skey", Payload: []byte("SKEY=$5075626c6963204b6579\n\x00")}); err != nil {
		t.Fatal(err)
	}
	skey, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantSKey := []byte("SKEY=$" + localSessionKeyHex + "\nDP=LOCAL\n\x00")
	if skey.Type != "skey" || skey.ID != 0 || !bytes.Equal(skey.Payload, wantSKey) {
		t.Fatalf("skey response = type %q, id %d, payload %q", skey.Type, skey.ID, skey.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "news", Payload: []byte("NAME=client.cfg\x00")}); err != nil {
		t.Fatal(err)
	}
	news, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if news.Type != "news" || news.ID != 0 || !bytes.Equal(news.Payload, []byte("QOS_PORT=0\n\x00")) {
		t.Fatalf("news response = type %q, id %d, payload %q", news.Type, news.ID, news.Payload)
	}

	selectionRequest := []byte("MYGAME=1 GAMES=0 ROOMS=0 USERS=1 MESGS=1 STATS=500\x00")
	if err := clientSecure.Write(easo.Frame{Type: "sele", ID: 9, Payload: selectionRequest}); err != nil {
		t.Fatal(err)
	}
	selection, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantSelection := []byte("MORE=0\nSLOTS=0\nSTATS=0\n\x00")
	if selection.Type != "sele" || selection.ID != 9 || !bytes.Equal(selection.Payload, wantSelection) {
		t.Fatalf("sele response = type %q, id %d, payload %q", selection.Type, selection.ID, selection.Payload)
	}

	authRequest := []byte("VERS=BURNOUT5/ISLAND\nNAME=asdf\nPASS=\"transformed-secret\"\n\x00")
	if err := clientSecure.Write(easo.Frame{Type: "auth", ID: 10, Payload: authRequest}); err != nil {
		t.Fatal(err)
	}
	auth, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantAuth := []byte("NAME=asdf\nPERSONAS=asdf\nMAIL=asdf@localhost\nADDR=127.0.0.1\nNUCLEUSMSG=0\nSPAMMABLE=0\nSPAMDEFAULT=NNN\n\x00")
	if auth.Type != "auth" || auth.ID != 10 || !bytes.Equal(auth.Payload, wantAuth) {
		t.Fatalf("auth response = type %q, id %d, payload %q", auth.Type, auth.ID, auth.Payload)
	}

	personaRequest := []byte("PERS=asdf\nLOGD=local-login-data\nMAC=$001122334455\nCDEV=\n\x00")
	if err := clientSecure.Write(easo.Frame{Type: "pers", ID: 11, Payload: personaRequest}); err != nil {
		t.Fatal(err)
	}
	persona, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantPersona := []byte("PERS=asdf\nLKEY=" + localPersonaLoginKey + "\nIDLE=120000\n\x00")
	if persona.Type != "pers" || persona.ID != 11 || !bytes.Equal(persona.Payload, wantPersona) {
		t.Fatalf("pers response = type %q, id %d, payload %q", persona.Type, persona.ID, persona.Payload)
	}

	presence, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantPresence := []byte("I=1\nN=asdf\nF=\nP=PC\nS=\nX=\nG=0\nA=127.0.0.1\nLA=127.0.0.1\n\x00")
	if presence.Type != "+who" || presence.ID != 0 || !bytes.Equal(presence.Payload, wantPresence) {
		t.Fatalf("presence notification = type %q, id %d, payload %q", presence.Type, presence.ID, presence.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "fget", ID: 12, Payload: []byte("TAG=F\n\x00")}); err != nil {
		t.Fatal(err)
	}
	features, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if features.Type != "fget" || features.ID != 12 || !bytes.Equal(features.Payload, []byte("F=\n\x00")) {
		t.Fatalf("fget response = type %q, id %d, payload %q", features.Type, features.ID, features.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "news", ID: 13, Payload: []byte("NAME=8\n\x00")}); err != nil {
		t.Fatal(err)
	}
	gameNews, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if gameNews.Type != "news" || gameNews.ID != 0x6e657738 || !bytes.Equal(gameNews.Payload, []byte("SPAMMABLE=0\nSPAMDEFAULT=NNN\n\x00")) {
		t.Fatalf("numeric news response = type %q, id %d, payload %q", gameNews.Type, gameNews.ID, gameNews.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "usld", ID: 14, Payload: []byte{0}}); err != nil {
		t.Fatal(err)
	}
	userSets, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if userSets.Type != "usld" || userSets.ID != 14 || !bytes.Equal(userSets.Payload, []byte{0}) {
		t.Fatalf("user-set response = type %q, id %d, payload %q", userSets.Type, userSets.ID, userSets.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "slst", ID: 15, Payload: []byte("LOC=%00%00%00%00\n\x00")}); err != nil {
		t.Fatal(err)
	}
	sessions, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if sessions.Type != "slst" || sessions.ID != 15 || !bytes.Equal(sessions.Payload, []byte("COUNT=0\n\x00")) {
		t.Fatalf("session-list response = type %q, id %d, payload %q", sessions.Type, sessions.ID, sessions.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "rent", ID: 16, Payload: []byte{0}}); err != nil {
		t.Fatal(err)
	}
	entitlements, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if entitlements.Type != "rent" || entitlements.ID != 16 || !bytes.Equal(entitlements.Payload, []byte("GFIDS=0\n\x00")) {
		t.Fatalf("entitlement response = type %q, id %d, payload %q", entitlements.Type, entitlements.ID, entitlements.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "rrlc", ID: 17, Payload: []byte("SKEY=\nNUM=10\nIDX=0\nSET=0\n\x00")}); err != nil {
		t.Fatal(err)
	}
	rankList, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantRankList := []byte("0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\x00")
	if rankList.Type != "rrlc" || rankList.ID != 17 || !bytes.Equal(rankList.Payload, wantRankList) {
		t.Fatalf("rank-list response = type %q, id %d, payload %q", rankList.Type, rankList.ID, rankList.Payload)
	}

	rankRequest := []byte("R=0,1,2,3,4,5,6,7,8,9\nSET=0\n\x00")
	if err := clientSecure.Write(easo.Frame{Type: "rrgt", ID: 18, Payload: rankRequest}); err != nil {
		t.Fatal(err)
	}
	rankResults, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantRankResults := []byte(strings.TrimSuffix(strings.Repeat("0,0,", 20), ",") + "\x00")
	if rankResults.Type != "rrgt" || rankResults.ID != 18 || !bytes.Equal(rankResults.Payload, wantRankResults) {
		t.Fatalf("rank-results response = type %q, id %d, payload %q", rankResults.Type, rankResults.ID, rankResults.Payload)
	}

	rankUploadRequest := []byte("SKEY=\nR=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14\nV=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\nC=????????????,????????????,????????????,????????????,????????????,????????????,????????????,????????????,????????????,????????????,????????????,????????????,????????????,????????????,????????????\nU=$1dd37c0e268cb30\nSET=0\n\x00")
	if err := clientSecure.Write(easo.Frame{Type: "rrup", ID: 19, Payload: rankUploadRequest}); err != nil {
		t.Fatal(err)
	}
	rankUpload, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if rankUpload.Type != "rrup" || rankUpload.ID != 19 || !bytes.Equal(rankUpload.Payload, []byte("VALID=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14\n\x00")) {
		t.Fatalf("rank-upload response = type %q, id %d, payload %q", rankUpload.Type, rankUpload.ID, rankUpload.Payload)
	}

	gameCreateRequest := []byte("NAME=asdf\nPASS=hidden\nPARAMS=,,,d800b87\nMINSIZE=2\nMAXSIZE=9\nCUSTFLAGS=413278208\nSYSFLAGS=64\nPRIV=0\nSEED=0\nFORCE_LEAVE=1\nUSERPARAMS=PUSMC01?????,,,ff,,d,,,f40906ab\nUSERFLAGS=0\n\x00")
	if err := clientSecure.Write(easo.Frame{Type: "gpsc", ID: 18, Payload: gameCreateRequest}); err != nil {
		t.Fatal(err)
	}
	gameCreate, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if gameCreate.Type != "gpsc" || gameCreate.ID != 18 || !bytes.Equal(gameCreate.Payload, []byte("COUNT=1\n\x00")) {
		t.Fatalf("game-create response = type %q, id %d, payload %q", gameCreate.Type, gameCreate.ID, gameCreate.Payload)
	}

	game, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantGame := getLocalGameRecord(gameCreateRequest, "asdf", "127.0.0.1", "127.0.0.1")
	if !bytes.Contains(wantGame, []byte("GAMEPORT=1024\n")) {
		t.Fatalf("game notification does not advertise retail peer port 1024: %q", wantGame)
	}
	if game.Type != "+gam" || game.ID != 0 || !bytes.Equal(game.Payload, wantGame) {
		t.Fatalf("game notification = type %q, id %d, payload %q", game.Type, game.ID, game.Payload)
	}
	presenceUpdate, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantPresenceUpdate := []byte("I=1\nN=asdf\nF=\nP=PC\nS=\nX=\nG=1\nA=127.0.0.1\nLA=127.0.0.1\n\x00")
	if presenceUpdate.Type != "+who" || presenceUpdate.ID != 0 || !bytes.Equal(presenceUpdate.Payload, wantPresenceUpdate) {
		t.Fatalf("game presence update = type %q, id %d, payload %q", presenceUpdate.Type, presenceUpdate.ID, presenceUpdate.Payload)
	}
	myGame, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if myGame.Type != "+mgm" || myGame.ID != 0 || !bytes.Equal(myGame.Payload, wantGame) {
		t.Fatalf("active-game notification = type %q, id %d, payload %q", myGame.Type, myGame.ID, myGame.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "fupr", ID: 19, Payload: []byte("PRES=1\nJOIN=1\n\x00")}); err != nil {
		t.Fatal(err)
	}
	presenceAck, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if presenceAck.Type != "fupr" || presenceAck.ID != 19 || !bytes.Equal(presenceAck.Payload, []byte{0}) {
		t.Fatalf("presence-update response = type %q, id %d, payload %q", presenceAck.Type, presenceAck.ID, presenceAck.Payload)
	}

	rivalUpdateRequest := []byte("RIVAL0=,,,,,,,,,,,,guest\nRIVAL1=,,,,,,,,,,,,asdf\n\x00")
	if err := clientSecure.Write(easo.Frame{Type: "rvup", ID: 22, Payload: rivalUpdateRequest}); err != nil {
		t.Fatal(err)
	}
	rivalUpdate, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if rivalUpdate.Type != "rvup" || rivalUpdate.ID != 22 || !bytes.Equal(rivalUpdate.Payload, []byte{0}) {
		t.Fatalf("rival-update response = type %q, id %d, payload %q", rivalUpdate.Type, rivalUpdate.ID, rivalUpdate.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "gsea", ID: 20, Payload: []byte("CANCEL=1\n\x00")}); err != nil {
		t.Fatal(err)
	}
	searchCancel, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if searchCancel.Type != "gsea" || searchCancel.ID != 20 || !bytes.Equal(searchCancel.Payload, []byte{0}) {
		t.Fatalf("search-cancel response = type %q, id %d, payload %q", searchCancel.Type, searchCancel.ID, searchCancel.Payload)
	}

	gameUpdateRequest := []byte("NAME=asdf\nPARAMS=,,,d800b87\nIDENT=1\nSESS=local-bp-game-1\nFORCE_LEAVE=1\n\x00")
	if err := clientSecure.Write(easo.Frame{Type: "gset", ID: 20, Payload: gameUpdateRequest}); err != nil {
		t.Fatal(err)
	}
	gameUpdate, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if gameUpdate.Type != "gset" || gameUpdate.ID != 20 || !bytes.Equal(gameUpdate.Payload, []byte{0}) {
		t.Fatalf("game-update response = type %q, id %d, payload %q", gameUpdate.Type, gameUpdate.ID, gameUpdate.Payload)
	}
	gameChange, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	mergedGameRequest := mergeLocalGameRequest(gameCreateRequest, gameUpdateRequest)
	wantGameChange := getLocalGameRecord(mergedGameRequest, "asdf", "127.0.0.1", "127.0.0.1")
	if gameChange.Type != "+gam" || gameChange.ID != 0 || !bytes.Equal(gameChange.Payload, wantGameChange) {
		t.Fatalf("game-change notification = type %q, id %d, payload %q", gameChange.Type, gameChange.ID, gameChange.Payload)
	}
	activeGameChange, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if activeGameChange.Type != "+mgm" || activeGameChange.ID != 0 || !bytes.Equal(activeGameChange.Payload, wantGameChange) {
		t.Fatalf("active-game-change notification = type %q, id %d, payload %q", activeGameChange.Type, activeGameChange.ID, activeGameChange.Payload)
	}

	if err := clientSecure.Write(easo.Frame{Type: "gsta", ID: 23, Payload: []byte{0}}); err != nil {
		t.Fatal(err)
	}
	gameStart, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if gameStart.Type != "gsta" || gameStart.ID != 23 || !bytes.Equal(gameStart.Payload, []byte{0}) {
		t.Fatalf("game-start response = type %q, id %d, payload %q", gameStart.Type, gameStart.ID, gameStart.Payload)
	}
	// This test's pre-start flags are 64: starting must add 0x80000,
	// and update the application game record before the play notification.
	startedRequest := mergeLocalGameRequest(mergedGameRequest, []byte("SYSFLAGS=524352\n\x00"))
	wantGameStart := getLocalGameRecord(startedRequest, "asdf", "127.0.0.1", "127.0.0.1")
	for _, kind := range []string{"+gam", "+mgm", "+ses"} {
		gameStartEvent, err := clientSecure.Read()
		if err != nil {
			t.Fatal(err)
		}
		if gameStartEvent.Type != kind || gameStartEvent.ID != 0 || !bytes.Equal(gameStartEvent.Payload, wantGameStart) {
			t.Fatalf("game-start event = type %q, id %d, payload %q; want %s with started flags", gameStartEvent.Type, gameStartEvent.ID, gameStartEvent.Payload, kind)
		}
	}

	// A single-player lobby completes its result barrier with the first report.
	// It receives the acknowledgement first, then +gam/+mgm with the started
	// bit cleared. Repeated reports remain idempotent and emit no notifications.
	resultReports := []easo.Frame{
		{Type: "rank", ID: 0, Payload: []byte("WHEN=2026.9.3-3:43:11\nREPT=asdf\nAUTH=\nVENUE=0\nSKU=PC\nNAME0=asdf\nTEAM0=0\nWEIGHT0=0\nNAME1=fdsa\nTEAM1=1\nWEIGHT1=0\nGEN=1,2\nRACE0=,,75718\nSTAT=225,3186,,1,,,,,PUSMC01\n\x00")},
		{Type: "rank", ID: 0, Payload: []byte("WHEN=2026.9.3-3:43:10\nREPT=fdsa\nAUTH=\nVENUE=0\nSKU=PC\nNAME0=fdsa\nTEAM0=0\nWEIGHT0=0\nNAME1=asdf\nTEAM1=1\nWEIGHT1=0\nGEN=1,2\nRACE0=bf5c,,75718\nSTAT=1e9,6be8,,,,,,,PUSMC01\n\x00")},
	}
	resultReports = append(resultReports, easo.Frame{Type: "rank", ID: 24, Payload: resultReports[0].Payload})
	for i, report := range resultReports {
		if err := clientSecure.Write(report); err != nil {
			t.Fatal(err)
		}
		ack, err := clientSecure.Read()
		if err != nil {
			t.Fatal(err)
		}
		if ack.Type != "rank" || ack.ID != report.ID || !bytes.Equal(ack.Payload, []byte{0}) {
			t.Fatalf("event-result acknowledgement = %#v, want rank id=%d with NUL payload", ack, report.ID)
		}
		if i == 0 {
			for _, kind := range []string{"+gam", "+mgm"} {
				ended, err := clientSecure.Read()
				if err != nil {
					t.Fatal(err)
				}
				if ended.Type != kind || getPayloadField(ended.Payload, "SYSFLAGS") != "64" {
					t.Fatalf("post-race event = %#v, want %s with SYSFLAGS=64", ended, kind)
				}
			}
		}
	}

	if err := clientSecure.Write(easo.Frame{Type: "hchk", ID: 21, Payload: []byte{0}}); err != nil {
		t.Fatal(err)
	}
	hostCheck, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if hostCheck.Type != "hchk" || hostCheck.ID != 21 || !bytes.Equal(hostCheck.Payload, []byte{0}) {
		t.Fatalf("host-check response = type %q, id %d, payload %q", hostCheck.Type, hostCheck.ID, hostCheck.Payload)
	}

	acctRequest := []byte("NAME=asdf\nLKEY=local-bp-persona-session\nSHARE=1\nSPAM=NNN\n\x00")
	if err := clientSecure.Write(easo.Frame{Type: "acct", ID: 17, Payload: acctRequest}); err != nil {
		t.Fatal(err)
	}
	account, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantAccount := []byte("NAME=asdf\nPERSONAS=asdf\nMAIL=asdf@localhost\nADDR=127.0.0.1\nNUCLEUSMSG=0\nSPAMMABLE=0\nSPAMDEFAULT=NNN\nSPAM=NNN\n\x00")
	if account.Type != "acct" || account.ID != 17 || !bytes.Equal(account.Payload, wantAccount) {
		t.Fatalf("acct response = type %q, id %d, payload %q", account.Type, account.ID, account.Payload)
	}

	keepalive, err := clientSecure.Read()
	if err != nil {
		t.Fatal(err)
	}
	if keepalive.Type != "~png" || keepalive.ID != 0 || !bytes.Equal(keepalive.Payload, []byte{0}) {
		t.Fatalf("keepalive = type %q, id %d, payload %q", keepalive.Type, keepalive.ID, keepalive.Payload)
	}
	if err := clientSecure.Write(keepalive); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.SetDeadline(time.Now())
	_ = clientConn.Close()
}

func TestLocalRoadRuleUploadRecordAccepts128BitMaskAndRejectsMalformedEntries(t *testing.T) {
	request := []byte("R=0,1,64,127,128,3,bad,5\nV=10,20,30,40,50,nope,70,80\nC=car0,car1,car64,car127,car128,car3,,car5\n\x00")
	want := []byte("VALID=0,1,64,127,5\n\x00")
	if got := getLocalRoadRuleUploadRecord(request); !bytes.Equal(got, want) {
		t.Fatalf("road-rule upload response = %q, want %q", got, want)
	}
}

func TestMergeLocalGameRequestPreservesCreationOnlyFields(t *testing.T) {
	base := []byte("NAME=host\nPARAMS=old\nUSERPARAMS=player\nMINSIZE=2\nMAXSIZE=9\nCUSTFLAGS=413345024\nSYSFLAGS=64\nPRIV=0\nSEED=7\nUSERFLAGS=3\n\x00")
	update := []byte("NAME=host\nPARAMS=new\nCUSTFLAGS=413278208\nSYSFLAGS=64\n\x00")
	got := mergeLocalGameRequest(base, update)
	want := []byte("NAME=host\nPARAMS=new\nUSERPARAMS=player\nMINSIZE=2\nMAXSIZE=9\nCUSTFLAGS=413278208\nSYSFLAGS=64\nPRIV=0\nSEED=7\nUSERFLAGS=3\n\x00")
	if !bytes.Equal(got, want) {
		t.Fatalf("merged game request = %q, want %q", got, want)
	}
}

func TestLocalMultiplayerGameRecordContainsBothPlayers(t *testing.T) {
	request := []byte("NAME=host\nPARAMS=,,,d800b87\nMINSIZE=2\nMAXSIZE=9\nCUSTFLAGS=413278208\nSYSFLAGS=64\nPRIV=0\nSEED=0\n\x00")
	host := &serviceClient{
		personaID:   1,
		personaName: "host",
		address:     "192.168.1.10",
		userParams:  "host-params",
		userFlags:   "3",
	}
	guest := &serviceClient{
		personaID:   2,
		personaName: "guest",
		address:     "192.168.1.11",
		userParams:  "guest-params",
		userFlags:   "4",
	}
	record := getLocalMultiplayerGameRecord(request, host, []*serviceClient{host, guest}, "127.0.0.1")
	for _, field := range []string{
		"COUNT=2\n",
		"OPID0=1\n",
		"OPPO0=host\n",
		"ADDR0=192.168.1.10\n",
		"OPPART0=0\n",
		"OPPARAM0=host-params\n",
		"OPFLAG0=3\n",
		"OPID1=2\n",
		"OPPO1=guest\n",
		"ADDR1=192.168.1.11\n",
		"OPPART1=0\n",
		"OPPARAM1=guest-params\n",
		"OPFLAG1=4\n",
		"NUMPART=1\n",
		"PARTSIZE0=2\n",
	} {
		if !bytes.Contains(record, []byte(field)) {
			t.Fatalf("multiplayer game record %q does not contain %q", record, field)
		}
	}
}

func TestUpdateLocalLobbyRoutesHostPlayerUpdatesByPersona(t *testing.T) {
	host := &serviceClient{
		personaID: 1, personaName: "host", address: "192.168.1.10",
		userParams: "host-waiting", userFlags: "0",
	}
	guest := &serviceClient{
		personaID: 2, personaName: "guest", address: "192.168.1.11",
		userParams: "guest-waiting", userFlags: "0",
	}
	server := &Server{
		config: Config{AdvertiseAddress: "127.0.0.1"},
		lobby: &localLobby{
			request: []byte("NAME=host\nMINSIZE=2\nMAXSIZE=9\nSYSFLAGS=64\n\x00"),
			host:    host,
			players: []*serviceClient{host, guest},
		},
	}

	game, _, _, updated := server.updateLocalLobby(host,
		[]byte("USERPARAMS=host-ready\nUSERFLAGS=3\n\x00"))
	if !updated || host.userParams != "host-ready" || host.userFlags != "3" {
		t.Fatalf("untargeted host update: updated=%v host=%+v", updated, host)
	}
	if guest.userParams != "guest-waiting" || guest.userFlags != "0" {
		t.Fatalf("untargeted host update changed guest: %+v", guest)
	}
	if !bytes.Contains(game, []byte("OPPARAM0=host-ready\n")) ||
		!bytes.Contains(game, []byte("OPPARAM1=guest-waiting\n")) {
		t.Fatalf("untargeted host game record = %q", game)
	}

	game, _, _, updated = server.updateLocalLobby(host,
		[]byte("USERPARAMS=guest-ready\nUSERFLAGS=4\nPERS=GuEsT\n\x00"))
	if !updated || guest.userParams != "guest-ready" || guest.userFlags != "4" {
		t.Fatalf("targeted guest update: updated=%v guest=%+v", updated, guest)
	}
	if host.userParams != "host-ready" || host.userFlags != "3" {
		t.Fatalf("targeted guest update changed host: %+v", host)
	}
	if !bytes.Contains(game, []byte("OPPARAM0=host-ready\n")) ||
		!bytes.Contains(game, []byte("OPFLAG0=3\n")) ||
		!bytes.Contains(game, []byte("OPPARAM1=guest-ready\n")) ||
		!bytes.Contains(game, []byte("OPFLAG1=4\n")) {
		t.Fatalf("targeted guest game record = %q", game)
	}
}

func TestKickLocalLobbyPlayerRemovesGuestAndPreservesHost(t *testing.T) {
	host := &serviceClient{personaID: 1, personaName: "host", address: "192.168.1.10"}
	guest := &serviceClient{personaID: 2, personaName: "guest", address: "192.168.1.11"}
	server := &Server{
		config: Config{AdvertiseAddress: "127.0.0.1"},
		lobby: &localLobby{
			request: []byte("NAME=host\nMINSIZE=2\nMAXSIZE=9\nSYSFLAGS=64\n\x00"),
			host:    host,
			players: []*serviceClient{host, guest},
		},
	}

	game, players, clients, kicked, updated := server.kickLocalLobbyPlayer(host, "GuEsT")
	if !updated || kicked != guest {
		t.Fatalf("kick result: updated=%v kicked=%p, want %p", updated, kicked, guest)
	}
	if len(players) != 1 || players[0] != host || len(clients) != 1 || clients[0] != host {
		t.Fatalf("remaining players=%#v clients=%#v", players, clients)
	}
	if !bytes.Contains(game, []byte("COUNT=1\n")) ||
		!bytes.Contains(game, []byte("OPPO0=host\n")) ||
		bytes.Contains(game, []byte("OPPO1=guest\n")) {
		t.Fatalf("post-kick game record = %q", game)
	}

	if _, _, _, _, updated = server.kickLocalLobbyPlayer(guest, "host"); updated {
		t.Fatal("non-host was allowed to kick the host")
	}
}

func TestStartLocalLobbySetsAndPersistsStartedFlag(t *testing.T) {
	for _, initial := range []string{"4160", "528448", "", "invalid"} {
		t.Run(initial, func(t *testing.T) {
			host := &serviceClient{personaID: 1, personaName: "host", address: "192.168.1.10", userParams: "host-ready"}
			guest := &serviceClient{personaID: 2, personaName: "guest", address: "192.168.1.11", userParams: "guest-ready"}
			server := &Server{config: Config{AdvertiseAddress: "127.0.0.1"}}
			if _, _, _, ok := server.startLocalLobby(host); ok {
				t.Fatal("started a nonexistent lobby")
			}
			request := []byte("NAME=host\nMINSIZE=2\nMAXSIZE=9\nPARAMS=event\nSYSFLAGS=" + initial + "\n\x00")
			server.createLocalLobby(host, request)
			server.joinLocalLobby(guest)
			for _, unauthorized := range []*serviceClient{nil, guest} {
				if _, _, _, ok := server.startLocalLobby(unauthorized); ok {
					t.Fatal("non-host started the lobby")
				}
				if !bytes.Equal(server.lobby.request, request) {
					t.Fatal("unauthorized start changed the lobby")
				}
			}
			game, players, clients, ok := server.startLocalLobby(host)
			if !ok || len(players) != 2 || len(clients) != 2 {
				t.Fatalf("start result: ok=%v players=%d clients=%d", ok, len(players), len(clients))
			}
			wantFlags := "528448" // 4160 | 0x80000; preserve the lock and other flags.
			if initial == "" || initial == "invalid" {
				wantFlags = "524288"
			}
			if got := getPayloadField(game, "SYSFLAGS"); got != wantFlags {
				t.Fatalf("SYSFLAGS=%s, want %s", got, wantFlags)
			}
			if getPayloadField(server.lobby.request, "SYSFLAGS") != wantFlags || getPayloadField(game, "PARAMS") != "event" {
				t.Fatal("start did not persist flags or changed event parameters")
			}
			if getPayloadField(game, "OPPARAM0") != "host-ready" || getPayloadField(game, "OPPARAM1") != "guest-ready" {
				t.Fatal("start lost the players' readiness parameters")
			}
			// A subsequent player update must retain the server's started bit.
			after, _, _, _ := server.updateLocalLobby(guest, []byte("USERFLAGS=1\n\x00"))
			if getPayloadField(after, "SYSFLAGS") != wantFlags {
				t.Fatal("player update lost the started flag")
			}
			repeated, _, _, _ := server.startLocalLobby(host)
			if !bytes.Equal(after, repeated) {
				t.Fatal("repeated start changed the game record")
			}
		})
	}
}

func TestLobbyResultsClearStartedFlagOnlyAfterEveryPlayerReports(t *testing.T) {
	host := &serviceClient{personaID: 1, personaName: "host", address: "192.168.1.10"}
	guest := &serviceClient{personaID: 2, personaName: "guest", address: "192.168.1.11"}
	outsider := &serviceClient{personaID: 3, personaName: "outsider", address: "192.168.1.12"}
	server := &Server{config: Config{AdvertiseAddress: "127.0.0.1"}}
	server.createLocalLobby(host, []byte("NAME=host\nMINSIZE=2\nMAXSIZE=9\nSYSFLAGS=4160\n\x00"))
	server.joinLocalLobby(guest)
	started, _, _, ok := server.startLocalLobby(host)
	if !ok || getPayloadField(started, "SYSFLAGS") != "528448" {
		t.Fatalf("started game = %q, ok=%v", started, ok)
	}
	for _, reporter := range []*serviceClient{nil, outsider, guest, guest} {
		if _, _, _, complete := server.recordLocalLobbyResult(reporter); complete {
			t.Fatalf("result barrier completed early for reporter %p", reporter)
		}
		if getPayloadField(server.lobby.request, "SYSFLAGS") != "528448" {
			t.Fatal("incomplete result barrier cleared the started flag")
		}
	}
	ended, players, clients, complete := server.recordLocalLobbyResult(host)
	if !complete || len(players) != 2 || len(clients) != 2 {
		t.Fatalf("completed result barrier: complete=%v players=%d clients=%d", complete, len(players), len(clients))
	}
	if getPayloadField(ended, "SYSFLAGS") != "4160" {
		t.Fatalf("ended SYSFLAGS=%q, want 4160", getPayloadField(ended, "SYSFLAGS"))
	}
	if _, _, _, complete = server.recordLocalLobbyResult(host); complete {
		t.Fatal("duplicate result completed the already-ended barrier")
	}
}

func TestMultiplayerGameRecordPlacesRecipientFirstWithoutChangingHost(t *testing.T) {
	request := []byte("NAME=host\nMINSIZE=2\nMAXSIZE=9\nCUSTFLAGS=413278208\nSYSFLAGS=64\n\x00")
	host := &serviceClient{personaID: 1, personaName: "host", address: "192.168.1.10"}
	guest := &serviceClient{personaID: 2, personaName: "guest", address: "192.168.1.11"}
	ordered := getLocalPlayerFirst([]*serviceClient{host, guest}, guest)
	if len(ordered) != 2 || ordered[0] != guest || ordered[1] != host {
		t.Fatalf("recipient roster order = %#v", ordered)
	}
	record := getLocalMultiplayerGameRecord(request, host, ordered, "127.0.0.1")
	for _, field := range []string{
		"HOST=host\n",
		"GPSHOST=host\n",
		"OPID0=2\n",
		"OPPO0=guest\n",
		"OPID1=1\n",
		"OPPO1=host\n",
	} {
		if !bytes.Contains(record, []byte(field)) {
			t.Fatalf("guest-local game record %q does not contain %q", record, field)
		}
	}
}

func TestLobbyPresencePreservesSelfBetweenFrames(t *testing.T) {
	server, err := New(Config{
		AdvertiseAddress: "192.168.4.199", GamePort: 21842, SessionID: 1,
		Mask: DefaultMask, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The fourth join exposed this race, but every intermediate frame must be
	// safe for every recipient, irrespective of TCP batching or frame timing.
	players := make([]*serviceClient, 8)
	for i := range players {
		players[i] = &serviceClient{
			personaID: 100 + i, personaName: "player" + strconv.Itoa(i+1),
			address: "192.168.4.199", gamePort: firstInstanceGamePort + i,
			logger: server.config.Logger,
		}
	}
	request := []byte("NAME=player1\nMAXSIZE=8\nSYSFLAGS=64\n\x00")
	for count := 1; count <= len(players); count++ {
		for _, recipient := range players[:count] {
			t.Run(strconv.Itoa(count)+"/"+recipient.personaName, func(t *testing.T) {
				self := recipient.personaName
				selfUpdates, remoteUpdates, rosterUpdates := 0, 0, 0
				seenRemote := make(map[string]bool)
				recipient.write = func(frame easo.Frame) error {
					switch frame.Type {
					case "+who":
						// Retail copies +who directly into its local user record.
						self = getPayloadField(frame.Payload, "N")
						selfUpdates++
						if getPayloadField(frame.Payload, "I") != strconv.Itoa(recipient.personaID) {
							t.Errorf("+who changed local persona ID: %q", frame.Payload)
						}
					case "+usr":
						remote := getPayloadField(frame.Payload, "N")
						if remote == self || seenRemote[remote] {
							t.Errorf("invalid/duplicate remote presence: %q", frame.Payload)
						}
						// +usr only copies into self when its F self bit is set.
						if getPayloadField(frame.Payload, "F") != "" {
							t.Errorf("remote presence has unexpected flags: %q", frame.Payload)
						}
						seenRemote[remote] = true
						remoteUpdates++
					case "+mgm":
						rosterUpdates++
						if getPayloadField(frame.Payload, "OPPO0") != self ||
							getPayloadField(frame.Payload, "COUNT") != strconv.Itoa(count) {
							t.Errorf("roster disagrees with local user: %q", frame.Payload)
						}
						for _, player := range players[:count] {
							if player != recipient && !seenRemote[player.personaName] {
								t.Errorf("missing remote presence for %s", player.personaName)
							}
						}
					default:
						t.Errorf("unexpected join notification %q", frame.Type)
					}
					// Model a game tick after EACH frame, not just the final +mgm.
					if self != recipient.personaName {
						t.Errorf("after %s: self became %q, want %q", frame.Type, self, recipient.personaName)
					}
					return nil
				}
				game := getLocalMultiplayerGameRecord(request, players[0], players[:count], server.config.AdvertiseAddress)
				server.notifyLobby(game, players[:count], []*serviceClient{recipient}, true, false)
				if selfUpdates != 1 || remoteUpdates != count-1 || rosterUpdates != 1 {
					t.Errorf("notification counts: self=%d remote=%d roster=%d", selfUpdates, remoteUpdates, rosterUpdates)
				}
			})
		}
	}
}

func TestNotifyLobbyPersonalizesRosterForEachClient(t *testing.T) {
	server, err := New(Config{
		AdvertiseAddress: "127.0.0.1",
		GamePort:         21842,
		SessionID:        1,
		Mask:             DefaultMask,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := []byte("NAME=host\nMINSIZE=2\nMAXSIZE=9\nCUSTFLAGS=413278208\nSYSFLAGS=64\n\x00")
	var hostFrames, guestFrames []easo.Frame
	host := &serviceClient{
		personaID: 1, personaName: "host", address: "192.168.1.10",
		logger: server.config.Logger,
		write: func(frame easo.Frame) error {
			hostFrames = append(hostFrames, frame)
			return nil
		},
	}
	guest := &serviceClient{
		personaID: 2, personaName: "guest", address: "192.168.1.11",
		logger: server.config.Logger,
		write: func(frame easo.Frame) error {
			guestFrames = append(guestFrames, frame)
			return nil
		},
	}
	players := []*serviceClient{host, guest}
	game := getLocalMultiplayerGameRecord(request, host, players, "127.0.0.1")
	server.notifyLobby(game, players, players, false, true)
	if len(hostFrames) != 2 || len(guestFrames) != 2 {
		t.Fatalf("notification counts = host %d, guest %d", len(hostFrames), len(guestFrames))
	}
	if !bytes.Contains(hostFrames[0].Payload, []byte("OPPO0=host\n")) {
		t.Fatalf("host game record = %q", hostFrames[0].Payload)
	}
	if !bytes.Contains(guestFrames[0].Payload, []byte("OPPO0=guest\n")) ||
		!bytes.Contains(guestFrames[0].Payload, []byte("HOST=host\n")) {
		t.Fatalf("guest game record = %q", guestFrames[0].Payload)
	}
	if !bytes.Equal(hostFrames[0].Payload, hostFrames[1].Payload) ||
		!bytes.Equal(guestFrames[0].Payload, guestFrames[1].Payload) {
		t.Fatal("+gam and +mgm payloads differ for a recipient")
	}

	hostFrames = nil
	guestFrames = nil
	server.notifyLobby(game, players, players, true, false)
	for name, frames := range map[string][]easo.Frame{"host": hostFrames, "guest": guestFrames} {
		if len(frames) != 3 {
			t.Fatalf("%s join notification count = %d", name, len(frames))
		}
		for _, frame := range frames {
			if frame.Type == "+gam" {
				t.Fatalf("%s join notifications contain duplicate collection update", name)
			}
		}
		if frames[2].Type != "+mgm" {
			t.Fatalf("%s final join notification = %q, want +mgm", name, frames[2].Type)
		}
		if frames[0].Type != "+usr" || frames[1].Type != "+who" {
			t.Fatalf("%s presence types = %q, %q; want remote +usr then local +who",
				name, frames[0].Type, frames[1].Type)
		}
	}
	if !bytes.Contains(hostFrames[0].Payload, []byte("N=guest\n")) ||
		!bytes.Contains(hostFrames[1].Payload, []byte("N=host\n")) {
		t.Fatalf("host presence order = %q, %q", hostFrames[0].Payload, hostFrames[1].Payload)
	}
	if !bytes.Contains(guestFrames[0].Payload, []byte("N=host\n")) ||
		!bytes.Contains(guestFrames[1].Payload, []byte("N=guest\n")) {
		t.Fatalf("guest presence order = %q, %q", guestFrames[0].Payload, guestFrames[1].Payload)
	}

	hostFrames = nil
	guestFrames = nil
	server.createLocalLobby(host, request)
	server.joinLocalLobby(guest)
	startedGame, startedPlayers, startedClients, started := server.startLocalLobby(host)
	if !started {
		t.Fatal("host could not start lobby")
	}
	server.notifyLobbyStart(startedGame, startedPlayers, startedClients)
	for name, frames := range map[string][]easo.Frame{"host": hostFrames, "guest": guestFrames} {
		if len(frames) != 3 {
			t.Fatalf("%s start notifications = %#v", name, frames)
		}
		for i, kind := range []string{"+gam", "+mgm", "+ses"} {
			if frames[i].Type != kind || frames[i].ID != 0 || !bytes.Equal(frames[i].Payload, frames[0].Payload) {
				t.Fatalf("%s start notification %d = %#v, want %s with identical record", name, i, frames[i], kind)
			}
			if getPayloadField(frames[i].Payload, "SYSFLAGS") != "524352" {
				t.Fatalf("%s start notification %s lacks started flag: %q", name, kind, frames[i].Payload)
			}
		}
	}
	if !bytes.Contains(hostFrames[0].Payload, []byte("OPPO0=host\n")) {
		t.Fatalf("host start record = %q", hostFrames[0].Payload)
	}
	if !bytes.Contains(guestFrames[0].Payload, []byte("OPPO0=guest\n")) ||
		!bytes.Contains(guestFrames[0].Payload, []byte("HOST=host\n")) {
		t.Fatalf("guest start record = %q", guestFrames[0].Payload)
	}
}

func TestServerJoinsSecondPersonaToSharedLobby(t *testing.T) {
	server, err := New(Config{
		AdvertiseAddress: "127.0.0.1",
		GamePort:         21842,
		SessionID:        1,
		Mask:             DefaultMask,
	})
	if err != nil {
		t.Fatal(err)
	}
	host := &serviceClient{personaID: server.personaIDFor("host"), personaName: "host", address: "192.168.1.10"}
	guest := &serviceClient{personaID: server.personaIDFor("guest"), personaName: "guest", address: "192.168.1.11"}
	if host.personaID == guest.personaID {
		t.Fatalf("host and guest received the same persona ID %d", host.personaID)
	}
	request := []byte("NAME=host\nMINSIZE=2\nMAXSIZE=9\nCUSTFLAGS=413278208\nSYSFLAGS=64\n\x00")
	server.createLocalLobby(host, request)
	record, players, clients, joined := server.joinLocalLobby(guest)
	if !joined || len(players) != 2 || len(clients) != 2 {
		t.Fatalf("join result = joined %v, players %d, clients %d", joined, len(players), len(clients))
	}
	if !bytes.Contains(record, []byte("COUNT=2\n")) || !bytes.Contains(record, []byte("OPID1=2\n")) {
		t.Fatalf("joined game record = %q", record)
	}
}

func TestAcceptedClientAddressPreservesSpecificLoopbackAlias(t *testing.T) {
	tests := []struct {
		name      string
		current   string
		announced string
		want      string
	}{
		{
			name:      "stock announcement does not erase process alias",
			current:   "127.0.0.2",
			announced: "127.0.0.1",
			want:      "127.0.0.2",
		},
		{
			name:      "specific alias replaces generic loopback",
			current:   "127.0.0.1",
			announced: "127.0.0.3",
			want:      "127.0.0.3",
		},
		{
			name:      "remote client cannot announce loopback",
			current:   "192.168.1.25",
			announced: "127.0.0.1",
			want:      "",
		},
		{
			name:      "routable announcement remains accepted",
			current:   "127.0.0.2",
			announced: "192.168.1.25",
			want:      "192.168.1.25",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := getAcceptedClientAddress(test.current, test.announced); got != test.want {
				t.Fatalf("getAcceptedClientAddress(%q, %q) = %q, want %q",
					test.current, test.announced, got, test.want)
			}
		})
	}
}

func TestServerAdvertisesThreePerPlayerPortsOnOneAddress(t *testing.T) {
	server, err := New(Config{
		AdvertiseAddress: "127.0.0.1",
		GamePort:         21842,
		SessionID:        1,
		Mask:             DefaultMask,
	})
	if err != nil {
		t.Fatal(err)
	}
	playersToJoin := []*serviceClient{
		{personaID: server.personaIDFor("host"), personaName: "host", address: "192.168.1.25", gamePort: 3659},
		{personaID: server.personaIDFor("guest"), personaName: "guest", address: "192.168.1.25", gamePort: 3660},
		{personaID: server.personaIDFor("third"), personaName: "third", address: "192.168.1.25", gamePort: 3661},
	}
	request := []byte("NAME=host\nMINSIZE=2\nMAXSIZE=9\nCUSTFLAGS=413278208\nSYSFLAGS=64\n\x00")
	server.createLocalLobby(playersToJoin[0], request)
	server.joinLocalLobby(playersToJoin[1])
	record, players, clients, joined := server.joinLocalLobby(playersToJoin[2])
	if !joined || len(players) != 3 || len(clients) != 3 {
		t.Fatalf("third join = joined %v, players %d, clients %d", joined, len(players), len(clients))
	}
	for _, field := range []string{
		"COUNT=3\n", "NUMPART=1\n", "GAMEPORT=1024\n", "PARTSIZE0=3\n",
		"ADDR0=192.168.1.25\n", "LADDR0=192.168.1.25\n", "MADDR0=BPPORT:3659\n", "OPPART0=0\n",
		"ADDR1=192.168.1.25\n", "LADDR1=192.168.1.25\n", "MADDR1=BPPORT:3660\n", "OPPART1=0\n",
		"ADDR2=192.168.1.25\n", "LADDR2=192.168.1.25\n", "MADDR2=BPPORT:3661\n", "OPPART2=0\n",
	} {
		if !bytes.Contains(record, []byte(field)) {
			t.Fatalf("three-player record %q does not contain %q", record, field)
		}
	}
	for _, invalid := range []string{"PARTSIZE1=", "PARTPARAMS1=", "PARTSIZE2=", "PARTPARAMS2="} {
		if bytes.Contains(record, []byte(invalid)) {
			t.Fatalf("three-player record %q unexpectedly contains %q", record, invalid)
		}
	}
}

func TestRemoteClientGamePortRecognizesPatchedRange(t *testing.T) {
	for _, test := range []struct {
		remote net.Addr
		want   int
	}{
		{remote: &net.TCPAddr{IP: net.ParseIP("192.168.1.25"), Port: 3659}, want: 3659},
		{remote: &net.TCPAddr{IP: net.ParseIP("192.168.1.25"), Port: 4095}, want: 4095},
		{remote: &net.TCPAddr{IP: net.ParseIP("192.168.1.25"), Port: 4096}, want: localPeerGamePort},
		{remote: nil, want: localPeerGamePort},
	} {
		if got := getRemoteClientGamePort(test.remote); got != test.want {
			t.Fatalf("getRemoteClientGamePort(%v) = %d, want %d", test.remote, got, test.want)
		}
	}
	for input, want := range map[string]int{
		"3659": 3659,
		"4095": 4095,
		"1024": 0,
		"4096": 0,
		"bad":  0,
	} {
		if got := getInstanceGamePort(input); got != want {
			t.Fatalf("getInstanceGamePort(%q) = %d, want %d", input, got, want)
		}
	}
}
