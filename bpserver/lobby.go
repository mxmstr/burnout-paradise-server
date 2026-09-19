package bpserver

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/local/reorigin-burnout-paradise/easo"
)

func getLocalPlayerFirst(players []*serviceClient, local *serviceClient) []*serviceClient {

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

func getLocalPlayerLast(players []*serviceClient, local *serviceClient) []*serviceClient {

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

func mergeLocalGameRequest(base, update []byte) []byte {

	keys := [...]string{
		"NAME", "PARAMS", "USERPARAMS", "MINSIZE", "MAXSIZE",
		"CUSTFLAGS", "SYSFLAGS", "PRIV", "SEED", "USERFLAGS",
	}

	var merged strings.Builder

	for _, key := range keys {
		value, found := getPayloadFieldValue(update, key)
		if !found {
			value, _ = getPayloadFieldValue(base, key)
		}
		merged.WriteString(key)
		merged.WriteByte('=')
		merged.WriteString(value)
		merged.WriteByte('\n')
	}

	merged.WriteByte(0)

	return []byte(merged.String())

}

func (s *Server) createLocalLobby(host *serviceClient, request []byte) ([]byte, []*serviceClient, []*serviceClient) {

	s.lobbyMu.Lock()
	defer s.lobbyMu.Unlock()

	host.address = getValidPlayerAddress(host.address, s.config.AdvertiseAddress)
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

	maxPlayers, err := strconv.Atoi(getPayloadField(s.lobby.request, "MAXSIZE"))
	if err != nil || maxPlayers < 1 {
		maxPlayers = 9
	}

	if len(s.lobby.players) >= maxPlayers {
		return nil, nil, nil, false
	}

	client.address = getValidPlayerAddress(client.address, s.config.AdvertiseAddress)
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

	if persona, found := getPayloadFieldValue(update, "PERS"); found && persona != "" {

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

		if value, found := getPayloadFieldValue(update, "USERPARAMS"); found {
			target.userParams = value
		}

		if value, found := getPayloadFieldValue(update, "USERFLAGS"); found {
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

	flags, _ := strconv.ParseInt(decimalField(getPayloadField(s.lobby.request, "SYSFLAGS"), "0"), 10, 32)
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

	flags, _ := strconv.ParseInt(decimalField(getPayloadField(s.lobby.request, "SYSFLAGS"), "0"), 10, 32)
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

	game := getLocalMultiplayerGameRecord(s.lobby.request, s.lobby.host, players, s.config.AdvertiseAddress)

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
		recipientPlayers := getLocalPlayerFirst(players, client)
		recipientGame := getLocalMultiplayerGameRecord(game, host, recipientPlayers, s.config.AdvertiseAddress)

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
			for _, player := range getLocalPlayerLast(players, client) {

				kind := "+usr"
				presence := getPresenceRecord(player.personaID, player.personaName, player.address, 1)

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
		recipientPlayers := getLocalPlayerFirst(players, client)
		recipientGame := getLocalMultiplayerGameRecord(game, host, recipientPlayers, s.config.AdvertiseAddress)
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
