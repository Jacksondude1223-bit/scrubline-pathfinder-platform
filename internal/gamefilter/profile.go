// Package gamefilter admits traffic to a game port only if it looks like that
// game.
//
// A UDP flood aimed at a game server is trivially distinguishable from play:
// the flood has the right destination port and nothing else right. The ASIC
// and the FPGA cannot see that, because neither matches on payload, so this
// runs on the PF_RING ZC stage where the packet is already in userspace.
//
// Nothing here is bound to a fixed list of games. An operator binds a profile
// to a port on a protected address through the policy, and a profile is
// either one of the built-ins or a signature written in the policy itself, so
// a game nobody anticipated needs configuration rather than a release.
package gamefilter

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Verdict is what the filter concluded about one packet.
type Verdict string

const (
	// VerdictPass means the packet is well-formed for its profile and its
	// source has cleared the gate.
	VerdictPass Verdict = "pass"
	// VerdictDrop means the packet is not this protocol, or its source has
	// not cleared the gate.
	VerdictDrop Verdict = "drop"
	// VerdictChallenge means the source must answer the protocol's own
	// challenge first. This packet is dropped and the reply is emitted.
	VerdictChallenge Verdict = "challenge"
	// VerdictUninspectable means no payload was supplied, so the filter has
	// nothing to judge. It never drops on this.
	VerdictUninspectable Verdict = "uninspectable"
)

// Result is one packet's outcome.
type Result struct {
	Verdict  Verdict
	Reason   string
	FilterID string
	Profile  string
	// Reply is the packet the datapath should send back to the source, for
	// profiles whose protocol defines a challenge. Empty otherwise.
	Reply []byte
}

// Magic is a byte sequence that must appear at a fixed offset.
type Magic struct {
	Offset int
	Bytes  []byte
}

// Signature is the shape a packet must have to be this protocol. Every field
// is optional; an empty signature accepts anything, which is only useful with
// a gate.
type Signature struct {
	MinLen int
	MaxLen int
	// AnyMagic passes if any one of these matches, which is how a protocol
	// with several framings is expressed.
	AnyMagic []Magic
	// PacketIDs restricts the first byte. Empty allows any.
	PacketIDs []byte
}

// Validate reports whether a payload has this signature.
func (s Signature) Validate(payload []byte) error {
	if s.MinLen > 0 && len(payload) < s.MinLen {
		return fmt.Errorf("packet is %d bytes, shorter than the %d this protocol allows", len(payload), s.MinLen)
	}
	if s.MaxLen > 0 && len(payload) > s.MaxLen {
		return fmt.Errorf("packet is %d bytes, longer than the %d this protocol allows", len(payload), s.MaxLen)
	}
	if len(s.PacketIDs) > 0 {
		if len(payload) == 0 {
			return errors.New("packet is empty and carries no packet id")
		}
		if !containsByte(s.PacketIDs, payload[0]) {
			return fmt.Errorf("packet id 0x%02x is not one this protocol sends", payload[0])
		}
	}
	if len(s.AnyMagic) > 0 {
		for _, m := range s.AnyMagic {
			if matchesMagic(payload, m) {
				return nil
			}
		}
		return errors.New("packet carries none of this protocol's magic sequences")
	}
	return nil
}

func matchesMagic(payload []byte, m Magic) bool {
	if m.Offset < 0 || len(m.Bytes) == 0 {
		return false
	}
	end := m.Offset + len(m.Bytes)
	if end > len(payload) {
		return false
	}
	return bytes.Equal(payload[m.Offset:end], m.Bytes)
}

func containsByte(set []byte, b byte) bool {
	for _, v := range set {
		if v == b {
			return true
		}
	}
	return false
}

// GateKind is how a source earns the right to send bulk traffic.
type GateKind string

const (
	// GateNone admits any well-formed packet. Validation only.
	GateNone GateKind = "none"
	// GateHandshake admits a source once it has been seen completing the
	// protocol's own opening sequence. Until then it may send only the
	// opening packet types.
	GateHandshake GateKind = "handshake"
	// GateChallenge answers the protocol's own challenge and admits a source
	// once it echoes the value back. Only protocols that define a challenge
	// can use this: inventing one would break every stock client, because a
	// client only echoes what its own protocol tells it to.
	GateChallenge GateKind = "challenge"
)

// Gate describes how a source clears a profile.
type Gate struct {
	Kind GateKind
	// OpenerIDs are the packet ids an unverified source may send.
	OpenerIDs []byte
	// CompleteIDs are the packet ids that finish the handshake. Seeing one
	// from a source admits it.
	CompleteIDs []byte

	// QueryIDs are the packet ids that trigger a challenge.
	QueryIDs []byte
	// ReplyPrefix is written before the cookie in the challenge reply.
	ReplyPrefix []byte
	// EchoOffset is where the cookie sits in a follow-up packet, and
	// CookieLen is how many bytes of it the protocol carries.
	EchoOffset int
	CookieLen  int
}

// Profile is a protocol the filter can recognise.
type Profile struct {
	Name      string
	Signature Signature
	Gate      Gate
	// SessionTTL is how long a source stays admitted without being seen
	// again. Zero takes the package default.
	SessionTTL time.Duration

	// Reasons for the verdicts a healthy packet gets, built once when the
	// profile is loaded rather than concatenated on every packet.
	reasonAdmitted   string
	reasonWellFormed string
}

// finalize precomputes the strings the pass path reports.
func (p Profile) finalize() Profile {
	switch p.Gate.Kind {
	case GateChallenge:
		p.reasonAdmitted = "source answered the " + p.Name + " challenge"
	default:
		p.reasonAdmitted = "source completed the " + p.Name + " handshake"
	}
	p.reasonWellFormed = "well-formed " + p.Name
	return p
}

// builtins are the profiles that ship with the filter. They are a
// convenience, not the mechanism: anything here could be written as a policy
// signature instead, and a game that is not here is configured rather than
// waited for.
var builtins = map[string]Profile{
	// RakNet, which Minecraft Bedrock and several other engines speak. Every
	// offline message carries a fixed 16-byte magic after the packet id, so
	// junk aimed at the port fails immediately. Connected datagrams have the
	// valid-packet bit set and carry no magic, which is why a source has to
	// complete the handshake before it can send them.
	"raknet": {
		Name: "raknet",
		Signature: Signature{
			MinLen: 1,
			MaxLen: 1500,
		},
		Gate: Gate{
			Kind: GateHandshake,
			// Unconnected ping, open connection request 1 and 2.
			OpenerIDs: []byte{0x01, 0x02, 0x05, 0x07},
			// Open connection request 2 is the last unconnected step.
			CompleteIDs: []byte{0x07},
		},
	},
	// The Valve query protocol, as used by Source and anything that speaks
	// A2S. Every query is prefixed with 0xFFFFFFFF, and the protocol has a
	// real challenge: the server answers 'A' with a four-byte number that
	// the client must repeat. That is what makes a gate possible here
	// without touching the client.
	"a2s": {
		Name: "a2s",
		Signature: Signature{
			MinLen:   5,
			MaxLen:   1400,
			AnyMagic: []Magic{{Offset: 0, Bytes: []byte{0xFF, 0xFF, 0xFF, 0xFF}}},
		},
		Gate: Gate{
			Kind: GateChallenge,
			// A2S_INFO, A2S_PLAYER, A2S_RULES.
			QueryIDs:    []byte{'T', 'U', 'V'},
			ReplyPrefix: []byte{0xFF, 0xFF, 0xFF, 0xFF, 'A'},
			// The echoed challenge follows the header and the query byte.
			EchoOffset: 5,
			CookieLen:  4,
		},
	},
}

// Builtin returns a profile that ships with the filter.
func Builtin(name string) (Profile, bool) {
	p, ok := builtins[strings.ToLower(name)]
	if !ok {
		return Profile{}, false
	}
	return p.finalize(), true
}

// BuiltinNames lists the profiles that ship with the filter.
func BuiltinNames() []string {
	out := make([]string, 0, len(builtins))
	for name := range builtins {
		out = append(out, name)
	}
	return out
}

// queryID reports whether a payload is one of the gate's query packets.
func (g Gate) queryID(payload []byte) bool {
	// The query byte follows the 4-byte header for A2S-shaped protocols; the
	// offset is wherever the echo starts minus one.
	idx := g.EchoOffset - 1
	if idx < 0 || idx >= len(payload) {
		return false
	}
	return containsByte(g.QueryIDs, payload[idx])
}
