package bpserver

import (
	"fmt"
	"strconv"
	"strings"
)

func getLocalRankListRecord(request []byte) []byte {

	num, err := strconv.Atoi(getPayloadField(request, "NUM"))
	if err != nil || num < 1 {
		num = 10
	}

	entries := num

	if getPayloadField(request, "SET") == "0" {
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

func getLocalRankResultsRecord(request []byte) []byte {

	ranks := 0

	for _, value := range strings.Split(getPayloadField(request, "R"), ",") {
		if _, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			ranks++
		}
	}

	if ranks == 0 {
		ranks = 10
	}

	entries := ranks
	if getPayloadField(request, "SET") == "0" {
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

func getLocalRoadRuleUploadRecord(request []byte) []byte {

	ranks := strings.Split(getPayloadField(request, "R"), ",")
	values := strings.Split(getPayloadField(request, "V"), ",")
	cars := strings.Split(getPayloadField(request, "C"), ",")
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

func getLocalGameRecord(request []byte, persona, clientAddress, advertiseAddress string) []byte {

	player := &serviceClient{
		personaID:   localPersonaID,
		personaName: persona,
		address:     clientAddress,
		gamePort:    localPeerGamePort,
		userParams:  getPayloadField(request, "USERPARAMS"),
		userFlags:   decimalField(getPayloadField(request, "USERFLAGS"), "0"),
	}

	return getLocalMultiplayerGameRecord(request, player, []*serviceClient{player}, advertiseAddress)

}

func getLocalMultiplayerGameRecord(request []byte, host *serviceClient, players []*serviceClient, advertiseAddress string) []byte {

	persona := cleanFieldValue(host.personaName, 19, "LocalPlayer")
	name := cleanFieldValue(getPayloadField(request, "NAME"), 35, persona)
	params := cleanFieldValue(getPayloadField(request, "PARAMS"), 259, "")
	minSize := decimalField(getPayloadField(request, "MINSIZE"), "2")
	maxSize := decimalField(getPayloadField(request, "MAXSIZE"), "9")
	custFlags := decimalField(getPayloadField(request, "CUSTFLAGS"), "0")
	sysFlags := decimalField(getPayloadField(request, "SYSFLAGS"), "0")
	privacy := decimalField(getPayloadField(request, "PRIV"), "0")
	seed := decimalField(getPayloadField(request, "SEED"), "0")

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
		playerAddress := getValidPlayerAddress(player.address, advertiseAddress)
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
