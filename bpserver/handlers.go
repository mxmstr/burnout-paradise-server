package bpserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/local/reorigin-burnout-paradise/easo"
)

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

	var writeMu sync.Mutex
	readFrame := func() (easo.Frame, error) { return easo.Read(conn) }
	writeFrameRaw := func(frame easo.Frame) error { return easo.Write(conn, frame) }
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
			"payload_bytes", len(ticket.Payload), "fields", getSafeFields(ticket.Payload))

		if ticket.Type != "?tic" || ticket.ID != 0 || !bytes.Equal(ticket.Payload, serverChallenge[32:]) {
			logger.Warn("invalid service ticket", "type", ticket.Type, "id", ticket.ID,
				"payload_bytes", len(ticket.Payload))
			return
		}

		secure, err := easo.NewSecureEASO(conn, serverChallenge[:16], serverChallenge[16:32])
		if err != nil {
			logger.Warn("secure EASO setup failed", "error", err)
			return
		}

		readFrame = secure.Read
		writeFrameRaw = secure.Write

		logger.Info("service ticket accepted", "transport", "RC4+MD5-V2")

	}

	var gameCreateRequest []byte
	var service *serviceClient
	personaName := "LocalPlayer"
	clientAddress := getRemoteClientAddress(conn.RemoteAddr(), s.config.AdvertiseAddress)

	if role == "service" {
		service = &serviceClient{
			personaName: personaName,
			address:     clientAddress,
			gamePort:    getRemoteClientGamePort(conn.RemoteAddr()),
			write:       writeFrame,
			logger:      logger,
		}
		logger.Info("peer endpoint selected", "address", clientAddress, "game_port", service.gamePort)
		defer s.removeClientFromLobby(service)
	}

	var keepaliveOnce sync.Once

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
			"payload_bytes", len(frame.Payload), "fields", getSafeFields(frame.Payload))

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
			if accepted := getAcceptedClientAddress(clientAddress, getPayloadField(frame.Payload, "ADDR")); accepted != "" {
				clientAddress = accepted
				if service != nil {
					service.address = clientAddress
				}
			}
			if service != nil {
				if port := getRemoteClientGamePort(conn.RemoteAddr()); port != 0 {
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
			name := getPayloadField(frame.Payload, "NAME")
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
			name := getLocalAccountName(getPayloadField(frame.Payload, "NAME"))
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
			name := getLocalAccountName(getPayloadField(frame.Payload, "NAME"))
			spam := normalizeSpamPreference(getPayloadField(frame.Payload, "SPAM"))
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
			persona := getLocalAccountName(getPayloadField(frame.Payload, "PERS"))
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
			presence := getPresenceRecord(personaID, persona, s.config.AdvertiseAddress, 0)
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
			if err := s.write(logger, writeFrame, easo.Frame{Type: "rrlc", ID: frame.ID, Payload: getLocalRankListRecord(frame.Payload)}); err != nil {
				return
			}

		case "rrgt":
			// Each requested road-rule rank expands to one name/score record, or
			// two records for SET=0. The retail callback always consumes the full
			// requested page, so materialise every empty record as the parser's 0,0
			// sentinel instead of returning a short or empty list.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "rrgt", ID: frame.ID, Payload: getLocalRankResultsRecord(frame.Payload)}); err != nil {
				return
			}

		case "rrup":
			// A successful upload response carries the road-rule IDs accepted by
			// the server in VALID. DirtySDK turns this list into a 64-bit mask and
			// passes it to Burnout's rank-cache callback. A bare success response
			// would therefore complete the transaction while rejecting every
			// uploaded record.
			if err := s.write(logger, writeFrame, easo.Frame{Type: "rrup", ID: frame.ID, Payload: getLocalRoadRuleUploadRecord(frame.Payload)}); err != nil {
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

				service.userParams = getPayloadField(frame.Payload, "USERPARAMS")
				service.userFlags = decimalField(getPayloadField(frame.Payload, "USERFLAGS"), "0")
				game, players, clients := s.createLocalLobby(service, gameCreateRequest)
				s.notifyLobby(game, players, clients, true, true)

			} else {

				game := getLocalGameRecord(gameCreateRequest, personaName, clientAddress, s.config.AdvertiseAddress)
				if err := s.write(logger, writeFrame, easo.Frame{Type: "+gam", ID: 0, Payload: game}); err != nil {
					return
				}

				presence := getLocalPresenceRecord(personaName, s.config.AdvertiseAddress, 1)
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

			service.userParams = getPayloadField(frame.Payload, "USERPARAMS")
			service.userFlags = decimalField(getPayloadField(frame.Payload, "USERFLAGS"), "0")

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
			if getPayloadField(frame.Payload, "CANCEL") != "1" {
				logger.Warn("unsupported game search request", "fields", getSafeFields(frame.Payload))
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

				if kickedName, kick := getPayloadFieldValue(frame.Payload, "KICK"); kick && kickedName != "" {

					game, players, clients, kicked, updated := s.kickLocalLobbyPlayer(service, kickedName)
					if updated {

						reason := decimalField(getPayloadField(frame.Payload, "KICK_REASON"), "0")

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
				game := getLocalGameRecord(gameCreateRequest, personaName, clientAddress, s.config.AdvertiseAddress)

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
