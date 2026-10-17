package gamefilter

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

// Compile turns the policy's game filters into bindings the engine can run.
//
// A filter that cannot be compiled is an error rather than a skipped row: a
// binding silently missing from a node means a game port is unprotected and
// nothing says so.
func Compile(filters []model.GameFilter) ([]Binding, error) {
	out := make([]Binding, 0, len(filters))
	for i, f := range filters {
		b, err := compileOne(f)
		if err != nil {
			return nil, fmt.Errorf("games[%d] (%s): %w", i, f.ID, err)
		}
		out = append(out, b)
	}
	return out, nil
}

func compileOne(f model.GameFilter) (Binding, error) {
	b := Binding{
		ID:      f.ID,
		Proto:   strings.ToLower(f.Proto),
		DPort:   f.DPort,
		Observe: f.Observe,
	}
	if f.DstCIDR != "" {
		pfx, err := netip.ParsePrefix(f.DstCIDR)
		if err != nil {
			return Binding{}, fmt.Errorf("dst_cidr %q: %v", f.DstCIDR, err)
		}
		b.Dst, b.HasDst = pfx, true
	}

	switch {
	case f.Custom != nil && f.Profile != "":
		return Binding{}, fmt.Errorf("set either profile %q or a custom signature, not both", f.Profile)
	case f.Custom != nil:
		p, err := customProfile(*f.Custom)
		if err != nil {
			return Binding{}, err
		}
		b.Profile = p.finalize()
	case f.Profile != "":
		p, ok := Builtin(f.Profile)
		if !ok {
			return Binding{}, fmt.Errorf("unknown profile %q; built-ins are %v, or describe the protocol in custom",
				f.Profile, BuiltinNames())
		}
		b.Profile = p
	default:
		return Binding{}, fmt.Errorf("needs a profile or a custom signature")
	}
	return b, nil
}

// customProfile builds a profile from a signature written in the policy.
func customProfile(sig model.GameSignature) (Profile, error) {
	p := Profile{Name: "custom"}
	if sig.MinLen < 0 || sig.MaxLen < 0 {
		return Profile{}, fmt.Errorf("lengths must not be negative")
	}
	if sig.MaxLen > 0 && sig.MinLen > sig.MaxLen {
		return Profile{}, fmt.Errorf("min_len %d is above max_len %d", sig.MinLen, sig.MaxLen)
	}
	p.Signature.MinLen = sig.MinLen
	p.Signature.MaxLen = sig.MaxLen

	ids, err := toBytes(sig.PacketIDs, "packet_ids")
	if err != nil {
		return Profile{}, err
	}
	p.Signature.PacketIDs = ids

	for i, m := range sig.Magic {
		if m.Offset < 0 {
			return Profile{}, fmt.Errorf("magic[%d]: offset must not be negative", i)
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(m.Hex), "0x"))
		if err != nil {
			return Profile{}, fmt.Errorf("magic[%d]: %q is not hex: %v", i, m.Hex, err)
		}
		if len(raw) == 0 {
			return Profile{}, fmt.Errorf("magic[%d]: empty", i)
		}
		p.Signature.AnyMagic = append(p.Signature.AnyMagic, Magic{Offset: m.Offset, Bytes: raw})
	}

	switch strings.ToLower(sig.Gate) {
	case "", string(GateNone):
		p.Gate = Gate{Kind: GateNone}
	case string(GateHandshake):
		openers, err := toBytes(sig.OpenerIDs, "opener_ids")
		if err != nil {
			return Profile{}, err
		}
		complete, err := toBytes(sig.CompleteIDs, "complete_ids")
		if err != nil {
			return Profile{}, err
		}
		if len(complete) == 0 {
			return Profile{}, fmt.Errorf("a handshake gate needs complete_ids, or no source can ever be admitted")
		}
		p.Gate = Gate{Kind: GateHandshake, OpenerIDs: openers, CompleteIDs: complete}
	case string(GateChallenge):
		// Answering a challenge means emitting protocol-correct bytes. A
		// wrong guess at that framing breaks every client instead of failing
		// closed, so it is not something a policy can describe.
		return Profile{}, fmt.Errorf("a challenge gate cannot be described in a policy; use a built-in profile that defines one")
	default:
		return Profile{}, fmt.Errorf("unknown gate %q; use none or handshake", sig.Gate)
	}
	return p, nil
}

func toBytes(values []int, field string) ([]byte, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]byte, 0, len(values))
	for _, v := range values {
		if v < 0 || v > 255 {
			return nil, fmt.Errorf("%s: %d is not a byte", field, v)
		}
		out = append(out, byte(v))
	}
	return out, nil
}
