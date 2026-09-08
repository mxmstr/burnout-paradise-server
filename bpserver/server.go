// Package bpserver provides the first-stage Burnout Paradise EASO handshake.
package bpserver

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/local/reorigin-burnout-paradise/easo"
)

const DefaultMask = "dbbcc81057aa718bbdafe887591112b4"

// The retail client asks for a 16-byte application session key by sending the
// literal value "Public Key" in its initial skey request. DirtySDK stores the
// returned bytes for the later account-login exchange. Keep this deterministic
// while the authentication handlers are being reconstructed so captures and
// tests remain reproducible.
const localSessionKeyHex = "6c6f63616c2d62702d73657276657221" // "local-bp-server!"

// The pers response carries a separate, printable login key. DirtySDK keeps
// this value verbatim (up to 63 characters) and reuses it in later requests.
const localPersonaLoginKey = "local-bp-persona-session"

// DirtySDK's +who parser requires a positive numeric identity before the
// Burnout login controller can leave state 8. Keep the synthetic identity
// stable across local sessions.
const localPersonaID = 1

// The retail PC client advertises both TCP and UDP gameplay endpoints as
// ~1:1024 in the 384-byte gEA LAN lobby beacon emitted after gpsc. This is the
// peer gameplay port, not the EASO service listener configured by GamePort.
const localPeerGamePort = 1024

// Patched clients source-bind their EASO service connection in this range and
// reserve the matching UDP port. The service connection therefore advertises
// the selected peer port without adding a new client transaction.
const (
	firstInstanceGamePort = 3659
	lastInstanceGamePort  = 4095
)

// sub_7FFBD0 maps this wire SYSFLAGS bit to application flag 0x800.
// The race-launch wait in sub_655CC0 cannot advance until it is present.
const gameStartedSysFlag = 0x80000

// DirtySDK interprets IDLE as milliseconds. The server refreshes this window
// with ~png frames; the client echoes each frame as its acknowledgement.
const (
	serviceIdleTimeout     = 120 * time.Second
	serviceKeepalivePeriod = 20 * time.Second
)

var serverChallenge = mustDecodeHex(
	"ba55778b9e10d44294388f79f770afe3cec0ddfffba532a61ff67726dc862f51" +
		"04b224c1b76d7e1d649c57c7ae5071a1651b988d1baabfd3c3c77b4c0c08c998" +
		"e6ccd21cea00f94b90bdd38cd08838fd5d4506e2",
)

type Config struct {
	AdvertiseAddress string
	GamePort         int
	SessionID        uint32
	Mask             string
	Logger           *slog.Logger
}

type Server struct {
	config          Config
	keepalivePeriod time.Duration
	lobbyMu         sync.Mutex
	nextPersonaID   int
	personaIDs      map[string]int
	lobby           *localLobby
}

type serviceClient struct {
	personaID   int
	personaName string
	address     string
	gamePort    int
	userParams  string
	userFlags   string
	write       func(easo.Frame) error
	logger      *slog.Logger
}

type localLobby struct {
	request       []byte
	host          *serviceClient
	players       []*serviceClient
	resultReports map[*serviceClient]struct{}
}

func New(config Config) (*Server, error) {
	if net.ParseIP(config.AdvertiseAddress) == nil {
		return nil, fmt.Errorf("advertise address %q is not an IP address", config.AdvertiseAddress)
	}
	if config.GamePort < 1 || config.GamePort > 65535 {
		return nil, fmt.Errorf("game port %d is invalid", config.GamePort)
	}
	if _, err := hex.DecodeString(config.Mask); err != nil || len(config.Mask) != 32 {
		return nil, errors.New("mask must contain exactly 32 hexadecimal characters")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Server{
		config:          config,
		keepalivePeriod: serviceKeepalivePeriod,
		nextPersonaID:   localPersonaID,
		personaIDs:      make(map[string]int),
	}, nil
}

// Serve accepts connections until the listener closes or ctx is cancelled.
func (s *Server) Serve(ctx context.Context, listener net.Listener, role string) error {
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleConnection(ctx, conn, role)
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn, role string) {
	defer conn.Close()
	connectionCtx, cancelConnection := context.WithCancel(ctx)
	defer cancelConnection()
	logger := s.config.Logger.With("role", role, "remote", conn.RemoteAddr())
	logger.Info("client connected")

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	readFrame := func() (easo.Frame, error) { return easo.Read(conn) }
	writeFrameRaw := func(frame easo.Frame) error { return easo.Write(conn, frame) }
	var writeMu sync.Mutex
	writeFrame := func(frame easo.Frame) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writeFrameRaw(frame)
	}
	if role == "service" {
		ticket, err := readFrame()
		if err != nil {
			logger.Warn("service ticket read failed", "error", err)
			return
		}
		logger.Info("inbound frame", "type", ticket.Type, "id", ticket.ID,
			"payload_bytes", len(ticket.Payload), "fields", safeFields(ticket.Payload))
		if ticket.Type != "?tic" || ticket.ID != 0 || !bytes.Equal(ticket.Payload, serverChallenge[32:]) {
			logger.Warn("invalid service ticket", "type", ticket.Type, "id", ticket.ID,
				"payload_bytes", len(ticket.Payload))
			return
		}
		secure, err := newSecureEASO(conn, serverChallenge[:16], serverChallenge[16:32])
		if err != nil {
			logger.Warn("secure EASO setup failed", "error", err)
			return
		}
		readFrame = secure.Read
		writeFrameRaw = secure.Write
		logger.Info("service ticket accepted", "transport", "RC4+MD5-V2")
	}

	var keepaliveOnce sync.Once
	personaName := "LocalPlayer"
	clientAddress := remoteClientAddress(conn.RemoteAddr(), s.config.AdvertiseAddress)
	var gameCreateRequest []byte
	var service *serviceClient
	if role == "service" {
		service = &serviceClient{
			personaName: personaName,
			address:     clientAddress,
			gamePort:    remoteClientGamePort(conn.RemoteAddr()),
			write:       writeFrame,
			logger:      logger,
		}
		logger.Info("peer endpoint selected", "address", clientAddress, "game_port", service.gamePort)
		defer s.removeClientFromLobby(service)
	}
	startKeepalive := func() {
		if role != "service" {
			return
		}
		keepaliveOnce.Do(func() {
			go func() {
				ticker := time.NewTicker(s.keepalivePeriod)
				defer ticker.Stop()
				for {
					select {
					case <-connectionCtx.Done():
						return
					case <-ticker.C:
						// An absent REF makes DirtySDK use its local clock. A single
						// NUL is the canonical empty EASO field list and is echoed
						// verbatim by the retail client.
						frame := easo.Frame{Type: "~png", Payload: []byte{0}}
						if err := s.write(logger, writeFrame, frame); err != nil {
							_ = conn.Close()
							return
						}
					}
				}
			}()
		})
	}

	for {
		frame, err := readFrame()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				logger.Warn("connection ended", "error", err)
			} else {
				logger.Info("client disconnected")
			}
			return
		}

		logger.Info("inbound frame", "type", frame.Type, "id", frame.ID,
			"payload_bytes", len(frame.Payload), "fields", safeFields(frame.Payload))

		switch frame.Type {
		case "@tic":
			if !strings.HasPrefix(string(frame.Payload), "RC4+MD5-V2") {
				logger.Warn("unsupported cipher offer")
				continue
			}
			if err := s.write(logger, writeFrame, easo.Frame{Type: "@tic", ID: frame.ID, Payload: serverChallenge}); err != nil {
				return
			}

		case "?tic":
			logger.Warn("unexpected service ticket after channel setup")

		case "@dir":
			payload := []byte(fmt.Sprintf("ADDR=%s\tPORT=%d\tSESS=%d\tMASK=%s\x00",
				s.config.AdvertiseAddress, s.config.GamePort, s.config.SessionID, s.config.Mask))
			if err := s.write(logger, writeFrame, easo.Frame{Type: "@dir", ID: frame.ID, Payload: payload}); err != nil {
				return
			}

		case "addr":
			// This is an unsolicited client address announcement, not a request.
			// DirtySDK does not register a response callback for it.
			if accepted := acceptedClientAddress(clientAddress, payloadField(frame.Payload, "ADDR")); accepted != "" {
				clientAddress = accepted
				if service != nil {
					service.address = clientAddress
				}
			}
			if service != nil {
				if port := instanceGamePort(payloadField(frame.Payload, "PORT")); port != 0 {
					if service.gamePort != port {
						logger.Info("peer game port updated from client announcement",
							"previous", service.gamePort, "game_port", port)
					}
					service.gamePort = port
				}
			}

		case "skey":
			payload := []byte("SKEY=$" + localSessionKeyHex + "\nDP=LOCAL\n\x00")
			if err := s.write(logger, writeFrame, easo.Frame{Type: "skey", ID: frame.ID, Payload: payload}); err != nil {
				return
			}

		case "news":
			name := payloadField(frame.Payload, "NAME")
			responseID := frame.ID
			numericNews := false
			payload := []byte("QOS_PORT=0\n\x00")
			if len(name) == 1 && name[0] >= '0' && name[0] <= '9' {
				// Numeric game-news requests keep the response type "news" but put
				// the FOURCC newN in the message-ID word. DirtySDK queues the request
				// by type and its callback validates the ID separately. Putting newN
				// in Type leaves the request queued until its 30-second timeout.
				responseID = 0x6e657730 + uint32(name[0]-'0') // "new0" + N
				numericNews = true
				// The login state machine reads these flags from the completed
				// new8 transaction (rather than retaining the auth response). A
				// value of one raises a front-end consent event and waits for UI
				// input indefinitely in this PC flow. Zero makes DirtySDK submit
				// the supplied defaults through the acct transaction below.
				payload = []byte("SPAMMABLE=0\nSPAMDEFAULT=NNN\n\x00")
			}
			if err := s.write(logger, writeFrame, easo.Frame{Type: "news", ID: responseID, Payload: payload}); err != nil {
				return
			}
			if numericNews {
				startKeepalive()
			}

		case "sele":
			// The initial feature-selection request completes when DirtySDK sees
			// a successful same-type frame. These optional fields default to zero
			// in the retail parser; state them explicitly while the corresponding
			// multipart/statistics services remain unimplemented.
			payload := []byte("MORE=0\nSLOTS=0\nSTATS=0\n\x00")
			if err := s.write(logger, writeFrame, easo.Frame{Type: "sele", ID: frame.ID, Payload: payload}); err != nil {
				return
			}

		case "auth":
			// This emulator deliberately creates a local synthetic account and
			// does not validate the transformed PASS field. One PERSONAS entry
			// makes the retail client automatically continue with a pers request.
			name := localAccountName(payloadField(frame.Payload, "NAME"))
			payload := []byte(fmt.Sprintf(
				"NAME=%s\nPERSONAS=%s\nMAIL=%s@localhost\nADDR=%s\nNUCLEUSMSG=0\nSPAMMABLE=0\nSPAMDEFAULT=NNN\n\x00",
				name, name, name, s.config.AdvertiseAddress,
			))
			if err := s.write(logger, writeFrame, easo.Frame{Type: "auth", ID: frame.ID, Payload: payload}); err != nil {
				return
			}

		case "acct":
			// A non-spammable account makes Burnout submit its default privacy
			// settings automatically instead of waiting for a front-end consent
			// event. DirtySDK parses a successful acct response as a refreshed
			// account record, so retain the one synthetic persona in the reply.
			name := localAccountName(payloadField(frame.Payload, "NAME"))
			spam := normalizeSpamPreference(payloadField(frame.Payload, "SPAM"))
			payload := []byte(fmt.Sprintf(
				"NAME=%s\nPERSONAS=%s\nMAIL=%s@localhost\nADDR=%s\nNUCLEUSMSG=0\nSPAMMABLE=0\nSPAMDEFAULT=%s\nSPAM=%s\n\x00",
				name, name, name, s.config.AdvertiseAddress, spam, spam,
			))
			if err := s.write(logger, writeFrame, easo.Frame{Type: "acct", ID: frame.ID, Payload: payload}); err != nil {
				return
			}

		case "pers":
			// A successful persona login completes the retail client's second
			// authentication stage. IDLE is the maximum interval between inbound
			// server frames, in milliseconds. Leave enough headroom for the game's
			// blocking UPnP setup while periodic ~png frames maintain the session.
			persona := localAccountName(payloadField(frame.Payload, "PERS"))
			personaName = persona
			personaID := localPersonaID
			if service != nil {
				personaID = s.personaIDFor(persona)
				service.personaID = personaID
				service.personaName = persona
				service.address = clientAddress
			}
			payload := []byte(fmt.Sprintf(
				"PERS=%s\nLKEY=%s\nIDLE=%d\n\x00",
				persona, localPersonaLoginKey, serviceIdleTimeout.Milliseconds(),
			))
			if err := s.write(logger, writeFrame, easo.Frame{Type: "pers", ID: frame.ID, Payload: payload}); err != nil {
				return
			}

			// The pers callback clears DirtySDK's current-user record. The live
			// service then repopulated it with an unsolicited +who notification;
			// Burnout's login state 8 waits until the record's I field is positive.
			// The compact field names below come directly from DirtySDK's +who
			// parser (sub_885D70 in the retail executable).
			presence := presenceRecord(personaID, persona, s.config.AdvertiseAddress, 0)
			if err := s.write(logger, writeFrame, easo.Frame{Type: "+who", ID: 0, Payload: presence}); err != nil {
				return
			}

		case "fget":
			// The post-login feature lookup asks for TAG=F. Its retail callback
			// accepts a successful empty F list, which leaves all optional online
			// feature records disabled while allowing login to continue.
			payload := []byte("F=\n\x00")
			if err := s.write(logger, writeFrame, easo.Frame{Type: "fget", ID: frame.ID, Payload: payload}); err != nil {
				return
			}

		case "usld":
			// After loading the current +who record, Burnout asks DirtySDK to
			// load its user-set data. The callback treats any successful usld
			// frame as the serialized list; an empty NUL-terminated list is valid
			// and advances the login controller beyond state 12.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "usld", ID: frame.ID, Payload: []byte{0}}); err != nil {
				return
			}

		case "slst":
			// The initial session-list lookup supplies LOC as four binary zero
			// bytes. DirtySDK's slst callback accepts COUNT=0 as a complete empty
			// list; VIEW0..VIEWn are required only when COUNT is positive.
			payload := []byte("COUNT=0\n\x00")
			if err := s.write(logger, writeFrame, easo.Frame{Type: "slst", ID: frame.ID, Payload: payload}); err != nil {
				return
			}

		case "rent":
			// Burnout requests its 64-bit game-feature/entitlement mask after
			// login. A zero mask is the safe local default while downloadable
			// entitlement persistence remains unimplemented.
			payload := []byte("GFIDS=0\n\x00")
			if err := s.write(logger, writeFrame, easo.Frame{Type: "rent", ID: frame.ID, Payload: payload}); err != nil {
				return
			}

		case "rrlc":
			// The rank-list parser produces parallel score/index arrays. SET=0 is
			// the split-screen form and consumes two entries per requested rank.
			// Returning only the two list-token words leaves those arrays
			// uninitialised and makes the retail callback index through stack data.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "rrlc", ID: frame.ID, Payload: localRankListRecord(frame.Payload)}); err != nil {
				return
			}

		case "rrgt":
			// Each requested road-rule rank expands to one name/score record, or
			// two records for SET=0. The retail callback always consumes the full
			// requested page, so materialise every empty record as the parser's 0,0
			// sentinel instead of returning a short or empty list.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "rrgt", ID: frame.ID, Payload: localRankResultsRecord(frame.Payload)}); err != nil {
				return
			}

		case "rrup":
			// A successful upload response carries the road-rule IDs accepted by
			// the server in VALID. DirtySDK turns this list into a 64-bit mask and
			// passes it to Burnout's rank-cache callback. A bare success response
			// would therefore complete the transaction while rejecting every
			// uploaded record.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "rrup", ID: frame.ID, Payload: localRoadRuleUploadRecord(frame.Payload)}); err != nil {
				return
			}

		case "gpsc":
			// A positive COUNT completes the creation transaction. +gam populates
			// the selected MYGAME collection. The intervening +who moves the local
			// user's G (current game) field to IDENT=1; Burnout rejects the +mgm
			// active-game event unless those identifiers already match.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "gpsc", ID: frame.ID, Payload: []byte("COUNT=1\n\x00")}); err != nil {
				return
			}
			gameCreateRequest = append(gameCreateRequest[:0], frame.Payload...)
			if service != nil {
				service.userParams = payloadField(frame.Payload, "USERPARAMS")
				service.userFlags = decimalField(payloadField(frame.Payload, "USERFLAGS"), "0")
				game, players, clients := s.createLocalLobby(service, gameCreateRequest)
				s.notifyLobby(game, players, clients, true, true)
			} else {
				game := localGameRecord(gameCreateRequest, personaName, clientAddress, s.config.AdvertiseAddress)
				if err := s.write(logger, writeFrame, easo.Frame{Type: "+gam", ID: 0, Payload: game}); err != nil {
					return
				}
				presence := localPresenceRecord(personaName, s.config.AdvertiseAddress, 1)
				if err := s.write(logger, writeFrame, easo.Frame{Type: "+who", ID: 0, Payload: presence}); err != nil {
					return
				}
				if err := s.write(logger, writeFrame, easo.Frame{Type: "+mgm", ID: 0, Payload: game}); err != nil {
					return
				}
			}

		case "gqwk", "gjoi":
			// Quick Join and direct Join Game use the same completion rule in the
			// retail adapter. Their same-type success response leaves the operation
			// pending; a matching +mgm active-game record completes it.
			if err := s.write(logger, writeFrame, easo.Frame{Type: frame.Type, ID: frame.ID, Payload: []byte{0}}); err != nil {
				return
			}
			if service == nil {
				continue
			}
			service.userParams = payloadField(frame.Payload, "USERPARAMS")
			service.userFlags = decimalField(payloadField(frame.Payload, "USERFLAGS"), "0")
			game, players, clients, joined := s.joinLocalLobby(service)
			if !joined {
				logger.Warn("join requested without an available local lobby", "type", frame.Type)
				continue
			}
			// The successful gqwk/gjoi operation is completed by one +mgm
			// active-game event. Sending +gam immediately before it makes the PC
			// mesh apply the new two-player roster twice and exhaust its one local
			// descriptor before +mgm handles the joining persona.
			s.notifyLobby(game, players, clients, true, false)

		case "gsea":
			// Burnout sends gsea CANCEL=1 after Quick Join/direct Join has
			// selected a game. This closes the search transaction only; the
			// player is already in the shared lobby and must not be removed or
			// sent another +mgm notification here.
			if payloadField(frame.Payload, "CANCEL") != "1" {
				logger.Warn("unsupported game search request", "fields", safeFields(frame.Payload))
				continue
			}
			if err := s.write(logger, writeFrame, easo.Frame{Type: "gsea", ID: frame.ID, Payload: []byte{0}}); err != nil {
				return
			}

		case "fupr":
			// Fire2's user-presence update callback advances solely on a successful
			// same-type response. The requested PRES/JOIN values have already been
			// reflected by the +who G=1 notification sent during game creation.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "fupr", ID: frame.ID, Payload: []byte{0}}); err != nil {
				return
			}

		case "rank":
			// sub_801340 uploads the local player's event results, using
			// sub_8004D0 as its completion callback. That callback reads only the
			// transaction error code, not a result payload. Acknowledge every
			// reporter independently; this does not persist or aggregate scores.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "rank", ID: frame.ID, Payload: []byte{0}}); err != nil {
				return
			}
			if service != nil {
				game, players, clients, complete := s.recordLocalLobbyResult(service)
				if complete {
					// sub_657A70 cannot advance the post-race flow while the
					// application game record still contains the started flag.
					// Update both collection and active-game views after every
					// current participant has submitted a result.
					s.notifyLobby(game, players, clients, false, true)
				}
			}

		case "rvup":
			// Burnout periodically uploads its current rival list after the lobby
			// roster changes. This is a client-to-server state update; its callback
			// only needs the matching transaction to complete successfully. Leaving
			// it pending makes the host close the service connection after 30 seconds.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "rvup", ID: frame.ID, Payload: []byte{0}}); err != nil {
				return
			}

		case "gset":
			// DirtySDK uses gset for update-game, update-player, kick, lock, and
			// unlock operations. The transaction callback reads only the error
			// code. +gam replaces the MYGAME collection record, while +mgm sends
			// the same record through DirtySDK's active-game event. Burnout's
			// EasyDrive event menu consumes the latter path: without it, the game
			// acknowledges event creation but leaves the local event state at
			// create (15/16). Merge this partial update into the creation request
			// so both notifications remain complete sub_885380 game records.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "gset", ID: frame.ID, Payload: []byte{0}}); err != nil {
				return
			}
			if service != nil {
				if kickedName, kick := payloadFieldValue(frame.Payload, "KICK"); kick && kickedName != "" {
					game, players, clients, kicked, updated := s.kickLocalLobbyPlayer(service, kickedName)
					if updated {
						reason := decimalField(payloadField(frame.Payload, "KICK_REASON"), "0")
						if kicked != nil && kicked.write != nil {
							_ = s.write(kicked.logger, kicked.write, easo.Frame{
								Type: "+kik", ID: 0,
								Payload: []byte("REASON=" + reason + "\n\x00"),
							})
						}
						s.notifyLobby(game, players, clients, false, true)
					}
				} else {
					game, players, clients, updated := s.updateLocalLobby(service, frame.Payload)
					if updated {
						s.notifyLobby(game, players, clients, false, true)
					}
				}
			} else if len(gameCreateRequest) != 0 {
				gameCreateRequest = mergeLocalGameRequest(gameCreateRequest, frame.Payload)
				game := localGameRecord(gameCreateRequest, personaName, clientAddress, s.config.AdvertiseAddress)
				if err := s.write(logger, writeFrame, easo.Frame{Type: "+gam", ID: 0, Payload: game}); err != nil {
					return
				}
				if err := s.write(logger, writeFrame, easo.Frame{Type: "+mgm", ID: 0, Payload: game}); err != nil {
					return
				}
			}

		case "gsta":
			// Start-game is an empty request issued by the lobby host after the
			// final game/player gset updates. Complete the transaction, then
			// publish the started flag through the active-game update path before
			// +ses. The play callback alone does not update the application record
			// whose SYSFLAGS is polled by the race-launch wait in sub_655CC0.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "gsta", ID: frame.ID, Payload: []byte{0}}); err != nil {
				return
			}
			if service != nil {
				game, players, clients, started := s.startLocalLobby(service)
				if started {
					s.notifyLobbyStart(game, players, clients)
				} else {
					logger.Warn("game start requested by a non-host client")
				}
			}

		case "hchk":
			// The host/content-check parser accepts HASH0 through HASH7. Missing
			// fields are deliberately decoded as eight zero hashes, which is the
			// appropriate local-server result while no content hashes are enforced.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "hchk", ID: frame.ID, Payload: []byte{0}}); err != nil {
				return
			}

		case "~png":
			// This is the retail client's acknowledgement of a server keepalive.
			// Do not echo it again or the peers would create a ping loop.

		default:
			logger.Warn("no application handler yet", "type", frame.Type)
		}
	}
}

func (s *Server) write(logger *slog.Logger, writeFrame func(easo.Frame) error, frame easo.Frame) error {
	if err := writeFrame(frame); err != nil {
		logger.Warn("write failed", "type", frame.Type, "error", err)
		return err
	}
	logger.Info("outbound frame", "type", frame.Type, "id", frame.ID, "payload_bytes", len(frame.Payload))
	return nil
}

func safeFields(payload []byte) []string {
	text := strings.TrimRight(string(payload), "\x00")
	parts := strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\t' })
	fields := make([]string, 0, len(parts))
	for _, part := range parts {
		key, value, found := strings.Cut(part, "=")
		if !found {
			if isPrintable(part) {
				fields = append(fields, part)
			}
			continue
		}
		switch strings.ToUpper(key) {
		case "PASS", "PASSWORD", "LKEY", "TOKEN", "AUTH", "NUCLEUSMSG":
			value = "<redacted>"
		}
		fields = append(fields, key+"="+value)
	}
	return fields
}

func payloadField(payload []byte, wanted string) string {
	text := strings.TrimRight(string(payload), "\x00")
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\t' }) {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found && strings.EqualFold(key, wanted) {
			return strings.Trim(strings.TrimSpace(value), "\"")
		}
	}
	return ""
}

func localAccountName(value string) string {
	var name strings.Builder
	for _, r := range value {
		if name.Len() >= 19 {
			break
		}
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			name.WriteRune(r)
		}
	}
	if name.Len() == 0 {
		return "LocalPlayer"
	}
	return name.String()
}

func normalizeSpamPreference(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 3 {
		return "NNN"
	}
	for _, r := range value {
		if r != 'Y' && r != 'N' {
			return "NNN"
		}
	}
	return value
}

func localPresenceRecord(persona, address string, gameID int) []byte {
	return presenceRecord(localPersonaID, persona, address, gameID)
}

func presenceRecord(personaID int, persona, address string, gameID int) []byte {
	persona = cleanFieldValue(persona, 19, "LocalPlayer")
	if net.ParseIP(address) == nil {
		address = "127.0.0.1"
	}
	return []byte(fmt.Sprintf(
		"I=%d\nN=%s\nF=\nP=PC\nS=\nX=\nG=%d\nA=%s\nLA=%s\n\x00",
		personaID, persona, gameID, address, address,
	))
}

func (s *Server) personaIDFor(persona string) int {
	s.lobbyMu.Lock()
	defer s.lobbyMu.Unlock()
	if id := s.personaIDs[persona]; id != 0 {
		return id
	}
	id := s.nextPersonaID
	s.nextPersonaID++
	s.personaIDs[persona] = id
	return id
}

func (s *Server) createLocalLobby(host *serviceClient, request []byte) ([]byte, []*serviceClient, []*serviceClient) {
	s.lobbyMu.Lock()
	defer s.lobbyMu.Unlock()
	host.address = validPlayerAddress(host.address, s.config.AdvertiseAddress)
	s.lobby = &localLobby{
		request:       append([]byte(nil), request...),
		host:          host,
		players:       []*serviceClient{host},
		resultReports: make(map[*serviceClient]struct{}),
	}
	return s.localLobbySnapshotLocked()
}

func (s *Server) joinLocalLobby(client *serviceClient) ([]byte, []*serviceClient, []*serviceClient, bool) {
	s.lobbyMu.Lock()
	defer s.lobbyMu.Unlock()
	if s.lobby == nil || s.lobby.host == nil {
		return nil, nil, nil, false
	}
	for _, player := range s.lobby.players {
		if player == client {
			game, players, clients := s.localLobbySnapshotLocked()
			return game, players, clients, true
		}
	}
	maxPlayers, err := strconv.Atoi(payloadField(s.lobby.request, "MAXSIZE"))
	if err != nil || maxPlayers < 1 {
		maxPlayers = 9
	}
	if len(s.lobby.players) >= maxPlayers {
		return nil, nil, nil, false
	}
	client.address = validPlayerAddress(client.address, s.config.AdvertiseAddress)
	s.lobby.players = append(s.lobby.players, client)
	game, players, clients := s.localLobbySnapshotLocked()
	return game, players, clients, true
}

func (s *Server) updateLocalLobby(client *serviceClient, update []byte) ([]byte, []*serviceClient, []*serviceClient, bool) {
	s.lobbyMu.Lock()
	defer s.lobbyMu.Unlock()
	if s.lobby == nil {
		return nil, nil, nil, false
	}

	// USERPARAMS/USERFLAGS belong to a player entry, not the game record.
	// During race launch the host first updates itself, then sends the same
	// fields with PERS=<guest> for every remote player.  Route those targeted
	// updates to the named lobby member so the following +mgm/+ses records carry
	// the ready/event state in each player's OPPARAM/OPFLAG fields.
	target := client
	if persona, found := payloadFieldValue(update, "PERS"); found && persona != "" {
		target = nil
		if client == s.lobby.host {
			for _, player := range s.lobby.players {
				if player != nil && strings.EqualFold(player.personaName, persona) {
					target = player
					break
				}
			}
		} else if strings.EqualFold(client.personaName, persona) {
			target = client
		}
	}
	if target != nil {
		if value, found := payloadFieldValue(update, "USERPARAMS"); found {
			target.userParams = value
		}
		if value, found := payloadFieldValue(update, "USERFLAGS"); found {
			target.userFlags = decimalField(value, "0")
		}
	}

	if s.lobby.host == client {
		s.lobby.request = mergeLocalGameRequest(s.lobby.request, update)
	}
	game, players, clients := s.localLobbySnapshotLocked()
	return game, players, clients, true
}

func (s *Server) startLocalLobby(client *serviceClient) ([]byte, []*serviceClient, []*serviceClient, bool) {
	s.lobbyMu.Lock()
	defer s.lobbyMu.Unlock()
	if s.lobby == nil || client == nil || s.lobby.host != client {
		return nil, nil, nil, false
	}
	flags, _ := strconv.ParseInt(decimalField(payloadField(s.lobby.request, "SYSFLAGS"), "0"), 10, 32)
	update := []byte(fmt.Sprintf("SYSFLAGS=%d\n\x00", flags|gameStartedSysFlag))
	s.lobby.request = mergeLocalGameRequest(s.lobby.request, update)
	s.lobby.resultReports = make(map[*serviceClient]struct{})
	game, players, clients := s.localLobbySnapshotLocked()
	return game, players, clients, true
}

func (s *Server) recordLocalLobbyResult(client *serviceClient) ([]byte, []*serviceClient, []*serviceClient, bool) {
	s.lobbyMu.Lock()
	defer s.lobbyMu.Unlock()
	if s.lobby == nil || client == nil {
		return nil, nil, nil, false
	}
	found := false
	for _, player := range s.lobby.players {
		if player == client {
			found = true
			break
		}
	}
	if !found {
		return nil, nil, nil, false
	}
	flags, _ := strconv.ParseInt(decimalField(payloadField(s.lobby.request, "SYSFLAGS"), "0"), 10, 32)
	if flags&gameStartedSysFlag == 0 {
		return nil, nil, nil, false
	}
	if s.lobby.resultReports == nil {
		s.lobby.resultReports = make(map[*serviceClient]struct{})
	}
	s.lobby.resultReports[client] = struct{}{}
	if len(s.lobby.resultReports) < len(s.lobby.players) {
		return nil, nil, nil, false
	}
	update := []byte(fmt.Sprintf("SYSFLAGS=%d\n\x00", flags&^gameStartedSysFlag))
	s.lobby.request = mergeLocalGameRequest(s.lobby.request, update)
	game, players, clients := s.localLobbySnapshotLocked()
	return game, players, clients, true
}

func (s *Server) kickLocalLobbyPlayer(client *serviceClient, persona string) ([]byte, []*serviceClient, []*serviceClient, *serviceClient, bool) {
	s.lobbyMu.Lock()
	defer s.lobbyMu.Unlock()
	if s.lobby == nil || s.lobby.host != client {
		return nil, nil, nil, nil, false
	}

	index := -1
	for i, player := range s.lobby.players {
		if player != nil && player != s.lobby.host && strings.EqualFold(player.personaName, persona) {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, nil, nil, nil, false
	}

	kicked := s.lobby.players[index]
	s.lobby.players = append(s.lobby.players[:index], s.lobby.players[index+1:]...)
	game, players, clients := s.localLobbySnapshotLocked()
	return game, players, clients, kicked, true
}

func (s *Server) localLobbySnapshotLocked() ([]byte, []*serviceClient, []*serviceClient) {
	if s.lobby == nil || s.lobby.host == nil {
		return nil, nil, nil
	}
	players := append([]*serviceClient(nil), s.lobby.players...)
	clients := append([]*serviceClient(nil), s.lobby.players...)
	game := localMultiplayerGameRecord(s.lobby.request, s.lobby.host, players, s.config.AdvertiseAddress)
	return game, players, clients
}

func (s *Server) notifyLobby(game []byte, players, clients []*serviceClient, includePresence, includeCollection bool) {
	if len(players) == 0 || players[0] == nil {
		return
	}
	host := players[0]
	for _, client := range clients {
		if client == nil || client.write == nil {
			continue
		}
		// The PC mesh adapter treats OPPO0 as the local player. A single
		// host-first record works for the host but makes a joining client's
		// local player occupy index one; sub_7FC460 then cannot acquire the
		// local mesh slot and sub_7FC290 dereferences its null result. Keep the
		// authoritative HOST/GPSHOST unchanged while ordering the roster for
		// each recipient.
		recipientPlayers := localPlayerFirst(players, client)
		recipientGame := localMultiplayerGameRecord(game, host, recipientPlayers, s.config.AdvertiseAddress)
		if includeCollection {
			if err := s.write(client.logger, client.write, easo.Frame{Type: "+gam", ID: 0, Payload: recipientGame}); err != nil {
				continue
			}
		}
		if includePresence {
			// +who (sub_885090) unconditionally replaces the local user record.
			// Remote users belong in +usr (sub_884D50), whose empty F field does
			// not mark them as self. Sending remote +who followed by a local one
			// is unsafe: the game can tick between frames and try to allocate a
			// second local descriptor, crashing in sub_7FC290 at 0x7FC2AD.
			for _, player := range localPlayerLast(players, client) {
				presence := presenceRecord(player.personaID, player.personaName, player.address, 1)
				kind := "+usr"
				if player == client {
					kind = "+who"
				}
				if err := s.write(client.logger, client.write, easo.Frame{Type: kind, ID: 0, Payload: presence}); err != nil {
					break
				}
			}
		}
		_ = s.write(client.logger, client.write, easo.Frame{Type: "+mgm", ID: 0, Payload: recipientGame})
	}
}

func (s *Server) notifyLobbyStart(game []byte, players, clients []*serviceClient) {
	if len(players) == 0 || players[0] == nil {
		return
	}
	host := players[0]
	for _, client := range clients {
		if client == nil || client.write == nil {
			continue
		}
		// sub_882CB0 parses +ses through the same complete game-record parser
		// used by +gam/+mgm. Preserve OPPO0 as the recipient's local player so
		// the play transition does not rebuild the mesh with a remote local slot.
		recipientPlayers := localPlayerFirst(players, client)
		recipientGame := localMultiplayerGameRecord(game, host, recipientPlayers, s.config.AdvertiseAddress)
		// +ses dispatches play but does not run sub_8005D0, which refreshes
		// the application's game flags. Publish both ordinary game views first
		// so the launch gate observes 0x80000, not just the earlier lock bit.
		for _, kind := range []string{"+gam", "+mgm", "+ses"} {
			if err := s.write(client.logger, client.write, easo.Frame{Type: kind, ID: 0, Payload: recipientGame}); err != nil {
				break
			}
		}
	}
}

func localPlayerFirst(players []*serviceClient, local *serviceClient) []*serviceClient {
	ordered := make([]*serviceClient, 0, len(players))
	for _, player := range players {
		if player == local {
			ordered = append(ordered, player)
			break
		}
	}
	for _, player := range players {
		if player != nil && player != local {
			ordered = append(ordered, player)
		}
	}
	return ordered
}

func localPlayerLast(players []*serviceClient, local *serviceClient) []*serviceClient {
	ordered := make([]*serviceClient, 0, len(players))
	for _, player := range players {
		if player != nil && player != local {
			ordered = append(ordered, player)
		}
	}
	for _, player := range players {
		if player == local {
			ordered = append(ordered, player)
			break
		}
	}
	return ordered
}

func (s *Server) removeClientFromLobby(client *serviceClient) {
	s.lobbyMu.Lock()
	if s.lobby == nil {
		s.lobbyMu.Unlock()
		return
	}
	if s.lobby.host == client {
		s.lobby = nil
		s.lobbyMu.Unlock()
		return
	}
	for i, player := range s.lobby.players {
		if player == client {
			s.lobby.players = append(s.lobby.players[:i], s.lobby.players[i+1:]...)
			game, players, clients := s.localLobbySnapshotLocked()
			s.lobbyMu.Unlock()
			s.notifyLobby(game, players, clients, false, true)
			return
		}
	}
	s.lobbyMu.Unlock()
}

func validPlayerAddress(address, fallback string) string {
	if net.ParseIP(address) != nil {
		return address
	}
	if net.ParseIP(fallback) != nil {
		return fallback
	}
	return "127.0.0.1"
}

func acceptedClientAddress(currentAddress, announcedAddress string) string {
	current := net.ParseIP(currentAddress)
	announced := net.ParseIP(announcedAddress)
	if announced == nil {
		return ""
	}
	if !announced.IsLoopback() {
		return announced.String()
	}
	if current == nil || !current.IsLoopback() {
		return ""
	}

	// The multi-instance ASI source-binds each local process to a distinct
	// 127.0.0.N address. Stock DirtySDK subsequently announces 127.0.0.1; do not
	// let that generic announcement collapse every process back to one endpoint.
	loopbackOne := net.ParseIP("127.0.0.1")
	if !current.Equal(loopbackOne) && announced.Equal(loopbackOne) {
		return current.String()
	}
	return announced.String()
}

func remoteClientAddress(remote net.Addr, fallback string) string {
	if remote != nil {
		if host, _, err := net.SplitHostPort(remote.String()); err == nil && net.ParseIP(host) != nil {
			return host
		}
	}
	return validPlayerAddress("", fallback)
}

func remoteClientGamePort(remote net.Addr) int {
	if remote != nil {
		if _, portText, err := net.SplitHostPort(remote.String()); err == nil {
			if port := instanceGamePort(portText); port != 0 {
				return port
			}
		}
	}
	return localPeerGamePort
}

func instanceGamePort(portText string) int {
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port < firstInstanceGamePort || port > lastInstanceGamePort {
		return 0
	}
	return port
}

func localRankListRecord(request []byte) []byte {
	num, err := strconv.Atoi(payloadField(request, "NUM"))
	if err != nil || num < 1 {
		num = 10
	}
	entries := num
	if payloadField(request, "SET") == "0" {
		entries *= 2
	}
	// DirtySDK's fixed response workspace contains 40 scores and 40 indices.
	if entries > 40 {
		entries = 40
	}
	tokens := make([]string, 2+entries)
	for i := range tokens {
		tokens[i] = "0"
	}
	return []byte(strings.Join(tokens, ",") + "\x00")
}

func localRankResultsRecord(request []byte) []byte {
	ranks := 0
	for _, value := range strings.Split(payloadField(request, "R"), ",") {
		if _, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			ranks++
		}
	}
	if ranks == 0 {
		ranks = 10
	}
	entries := ranks
	if payloadField(request, "SET") == "0" {
		entries *= 2
	}
	// The parser's fixed result contains 40 names, scores, and set indices.
	if entries > 40 {
		entries = 40
	}
	tokens := make([]string, 2*entries)
	for i := range tokens {
		tokens[i] = "0"
	}
	return []byte(strings.Join(tokens, ",") + "\x00")
}

func localRoadRuleUploadRecord(request []byte) []byte {
	ranks := strings.Split(payloadField(request, "R"), ",")
	values := strings.Split(payloadField(request, "V"), ",")
	cars := strings.Split(payloadField(request, "C"), ",")
	entries := len(ranks)
	if len(values) < entries {
		entries = len(values)
	}
	if len(cars) < entries {
		entries = len(cars)
	}

	valid := make([]string, 0, entries)
	seen := make(map[int]struct{}, entries)
	for i := 0; i < entries; i++ {
		rank, err := strconv.Atoi(strings.TrimSpace(ranks[i]))
		// The rrup parser constructs two 64-bit words. SET=0 uses all 128
		// road-rule slots; the other sets currently exercise the lower half.
		if err != nil || rank < 0 || rank >= 128 {
			continue
		}
		if _, err := strconv.ParseInt(strings.TrimSpace(values[i]), 10, 64); err != nil {
			continue
		}
		if strings.TrimSpace(cars[i]) == "" {
			continue
		}
		if _, duplicate := seen[rank]; duplicate {
			continue
		}
		seen[rank] = struct{}{}
		valid = append(valid, strconv.Itoa(rank))
	}

	return []byte("VALID=" + strings.Join(valid, ",") + "\n\x00")
}

func localGameRecord(request []byte, persona, clientAddress, advertiseAddress string) []byte {
	player := &serviceClient{
		personaID:   localPersonaID,
		personaName: persona,
		address:     clientAddress,
		gamePort:    localPeerGamePort,
		userParams:  payloadField(request, "USERPARAMS"),
		userFlags:   decimalField(payloadField(request, "USERFLAGS"), "0"),
	}
	return localMultiplayerGameRecord(request, player, []*serviceClient{player}, advertiseAddress)
}

func localMultiplayerGameRecord(request []byte, host *serviceClient, players []*serviceClient, advertiseAddress string) []byte {
	persona := cleanFieldValue(host.personaName, 19, "LocalPlayer")
	name := cleanFieldValue(payloadField(request, "NAME"), 35, persona)
	params := cleanFieldValue(payloadField(request, "PARAMS"), 259, "")
	minSize := decimalField(payloadField(request, "MINSIZE"), "2")
	maxSize := decimalField(payloadField(request, "MAXSIZE"), "9")
	custFlags := decimalField(payloadField(request, "CUSTFLAGS"), "0")
	sysFlags := decimalField(payloadField(request, "SYSFLAGS"), "0")
	privacy := decimalField(payloadField(request, "PRIV"), "0")
	seed := decimalField(payloadField(request, "SEED"), "0")
	if len(players) == 0 {
		players = []*serviceClient{host}
	}

	// This is the complete record consumed by sub_885380 in the retail PC
	// executable. Its parsed structure has room for only two partition records;
	// a third PARTSIZE/PARTPARAMS pair overlaps COUNT and the first player record.
	// The lobby is one partition containing every player. Individual peer
	// endpoints remain represented by ADDR/LADDR and the per-player port carrier.
	// GAMEPORT is the fixed peer endpoint advertised by the original PC build.
	var record strings.Builder
	fmt.Fprintf(&record,
		"IDENT=1\nNAME=%s\nHOST=%s\nGPSHOST=%s\nPARAMS=%s\nPLATPARAMS=\nROOM=0\n"+
			"CUSTFLAGS=%s\nSYSFLAGS=%s\nCOUNT=%d\nPRIV=%s\nMINSIZE=%s\nMAXSIZE=%s\n"+
			"NUMPART=1\nSEED=%s\nGAMEPORT=%d\nVOIPPORT=0\nGAMEMODE=0\nAUTH=\n"+
			"SESS=local-bp-game-1\n",
		name, persona, persona, params,
		custFlags, sysFlags, len(players), privacy, minSize, maxSize,
		seed, localPeerGamePort,
	)
	for i, player := range players {
		playerName := cleanFieldValue(player.personaName, 19, "LocalPlayer")
		playerAddress := validPlayerAddress(player.address, advertiseAddress)
		machineAddress := ""
		if player.gamePort >= firstInstanceGamePort && player.gamePort <= lastInstanceGamePort {
			// The stock EASO parser has no PORTn field, but it carries MADDRn into
			// the 148-byte mesh input. The ASI consumes this marker, writes the
			// external/internal physical ProtoTunnel ports while leaving the game
			// and voice ports virtual, and restores the canonical machine-address
			// value before DirtySDK sees it.
			machineAddress = fmt.Sprintf("BPPORT:%d", player.gamePort)
		}
		userParams := cleanFieldValue(player.userParams, 59, "")
		userFlags := decimalField(player.userFlags, "0")
		fmt.Fprintf(&record,
			"OPID%d=%d\nOPPO%d=%s\nADDR%d=%s\nLADDR%d=%s\nMADDR%d=%s\nOPPART%d=%d\n"+
				"OPPARAM%d=%s\nOPFLAG%d=%s\nPRES%d=0\nOPGUEST%d=\n",
			i, player.personaID, i, playerName, i, playerAddress, i, playerAddress, i, machineAddress, i, 0,
			i, userParams, i, userFlags, i, i,
		)
	}
	fmt.Fprintf(&record, "PARTSIZE0=%d\nPARTPARAMS0=\n", len(players))
	record.WriteByte(0)
	return []byte(record.String())
}

func mergeLocalGameRequest(base, update []byte) []byte {
	keys := [...]string{
		"NAME", "PARAMS", "USERPARAMS", "MINSIZE", "MAXSIZE",
		"CUSTFLAGS", "SYSFLAGS", "PRIV", "SEED", "USERFLAGS",
	}
	var merged strings.Builder
	for _, key := range keys {
		value, found := payloadFieldValue(update, key)
		if !found {
			value, _ = payloadFieldValue(base, key)
		}
		merged.WriteString(key)
		merged.WriteByte('=')
		merged.WriteString(value)
		merged.WriteByte('\n')
	}
	merged.WriteByte(0)
	return []byte(merged.String())
}

func payloadFieldValue(payload []byte, wanted string) (string, bool) {
	text := strings.TrimRight(string(payload), "\x00")
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\t' }) {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found && strings.EqualFold(key, wanted) {
			return strings.Trim(strings.TrimSpace(value), "\""), true
		}
	}
	return "", false
}

func cleanFieldValue(value string, max int, fallback string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\x00' || r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		if r < 0x20 || r > 0x7e {
			return '?'
		}
		return r
	}, value)
	if value == "" {
		value = fallback
	}
	if len(value) > max {
		value = value[:max]
	}
	return value
}

func decimalField(value, fallback string) string {
	if value == "" {
		return fallback
	}
	if _, err := strconv.ParseInt(value, 10, 32); err != nil {
		return fallback
	}
	return value
}

func isPrintable(value string) bool {
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return value != ""
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}

func ParseSessionID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err
}
