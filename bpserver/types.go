package bpserver

import (
	"log/slog"
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
