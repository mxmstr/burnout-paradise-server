package bpserver

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

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

func getValidPlayerAddress(address, fallback string) string {

	if net.ParseIP(address) != nil {
		return address
	}

	if net.ParseIP(fallback) != nil {
		return fallback
	}

	return "127.0.0.1"

}

func getRemoteClientAddress(remote net.Addr, fallback string) string {

	if remote != nil {
		if host, _, err := net.SplitHostPort(remote.String()); err == nil && net.ParseIP(host) != nil {
			return host
		}
	}

	return getValidPlayerAddress("", fallback)

}
func getAcceptedClientAddress(currentAddress, announcedAddress string) string {

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

func getInstanceGamePort(portText string) int {

	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil || port < firstInstanceGamePort || port > lastInstanceGamePort {
		return 0
	}

	return port

}

func getRemoteClientGamePort(remote net.Addr) int {

	if remote != nil {
		if _, portText, err := net.SplitHostPort(remote.String()); err == nil {
			if port := getInstanceGamePort(portText); port != 0 {
				return port
			}
		}
	}

	return localPeerGamePort

}

func getLocalPresenceRecord(persona, address string, gameID int) []byte {
	return getPresenceRecord(localPersonaID, persona, address, gameID)
}

func getPresenceRecord(personaID int, persona, address string, gameID int) []byte {

	persona = cleanFieldValue(persona, 19, "LocalPlayer")

	if net.ParseIP(address) == nil {
		address = "127.0.0.1"
	}

	return []byte(fmt.Sprintf(
		"I=%d\nN=%s\nF=\nP=PC\nS=\nX=\nG=%d\nA=%s\nLA=%s\n\x00",
		personaID, persona, gameID, address, address,
	))

}

func getPayloadFieldValue(payload []byte, wanted string) (string, bool) {

	text := strings.TrimRight(string(payload), "\x00")

	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\t' }) {

		key, value, found := strings.Cut(strings.TrimSpace(part), "=")

		if found && strings.EqualFold(key, wanted) {
			return strings.Trim(strings.TrimSpace(value), "\""), true
		}

	}

	return "", false

}

func getPayloadField(payload []byte, wanted string) string {

	text := strings.TrimRight(string(payload), "\x00")

	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\t' }) {

		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if found && strings.EqualFold(key, wanted) {
			return strings.Trim(strings.TrimSpace(value), "\"")
		}

	}

	return ""

}

func getSafeFields(payload []byte) []string {

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

func getLocalAccountName(value string) string {

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
