package pipeline

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

// referenceMatch is the original string-parsing matcher, kept verbatim as the
// oracle for the compiled path that replaced it. Decide pre-parses CIDRs at
// Load now; this proves that change did not move any matching decision.
func referenceMatch(m model.Match, f model.Flow) bool {
	contains := func(cidr, ip string) bool {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return false
		}
		return pfx.Contains(addr)
	}
	if m.SrcCIDR != "" && !contains(m.SrcCIDR, f.SrcIP) {
		return false
	}
	if m.DstCIDR != "" && !contains(m.DstCIDR, f.DstIP) {
		return false
	}
	if m.Proto != "" && m.Proto != "any" && !strings.EqualFold(m.Proto, f.Proto) {
		return false
	}
	if m.DPort != 0 && m.DPort != f.DPort {
		return false
	}
	if m.SPort != 0 && m.SPort != f.SPort {
		return false
	}
	if m.TCPFlags != "" && !strings.EqualFold(m.TCPFlags, f.Flags) {
		return false
	}
	return true
}

func TestCompiledMatchAgreesWithReference(t *testing.T) {
	cidrs := []string{
		"", "203.0.113.0/24", "203.0.113.10/32", "0.0.0.0/8", "198.51.100.0/24",
		"0.0.0.0/0", "10.0.0.0/8",
		// malformed: these never matched before, because the parse failed
		"203.0.113.0/99", "not-a-cidr", "garbage/8", "203.0.113.0",
		// v6, to be sure a v4 flow does not match one
		"2001:db8::/32",
	}
	protos := []string{"", "any", "tcp", "TCP", "udp", "icmp", "ANY"}
	flagSets := []string{"", "syn", "SYN", "syn,ack"}
	ips := []string{"203.0.113.10", "198.51.100.9", "10.1.2.3", "192.0.2.1", "", "bogus", "2001:db8::1"}
	ports := []int{0, 443, 19132}

	checked := 0
	for _, src := range cidrs {
		for _, dst := range cidrs {
			for _, proto := range protos {
				for _, flags := range flagSets {
					for _, dport := range ports {
						m := model.Match{SrcCIDR: src, DstCIDR: dst, Proto: proto, TCPFlags: flags, DPort: dport}
						cm := compileMatch(m)
						for _, sip := range ips {
							for _, dip := range ips {
								for _, fproto := range protos {
									for _, fflags := range flagSets {
										f := model.Flow{SrcIP: sip, DstIP: dip, Proto: fproto, Flags: fflags, DPort: dport, PPS: 10}
										k := flowKey{}
										k.src, k.srcOK = parseAddr(f.SrcIP)
										k.dst, k.dstOK = parseAddr(f.DstIP)
										want := referenceMatch(m, f)
										got := cm.matches(f, k)
										if got != want {
											t.Fatalf("mismatch\nrule %+v\nflow %+v\nreference=%v compiled=%v", m, f, want, got)
										}
										checked++
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("compiled matcher agreed with the reference on %d rule/flow combinations", checked)
}

// Ownership used to parse the prefix list per packet; it now uses the
// pre-parsed list. Same answers, including for malformed and v6 entries.
func TestOwnsAgreesWithStringParsing(t *testing.T) {
	prefixLists := [][]string{
		nil,
		{},
		{"203.0.113.0/24"},
		{"203.0.113.0/24", "203.0.114.10/32"},
		{"203.0.113.0/99"},
		{"not-a-cidr", "203.0.113.0/24"},
		{"0.0.0.0/0"},
		{"2001:db8::/32"},
	}
	ips := []string{"203.0.113.10", "203.0.114.10", "198.18.0.1", "", "bogus", "2001:db8::1"}
	for _, list := range prefixLists {
		p := New(model.Program{Prefixes: list})
		for _, ip := range ips {
			want := false
			if addr, err := netip.ParseAddr(ip); err == nil {
				for _, cidr := range list {
					if pfx, err := netip.ParsePrefix(cidr); err == nil && pfx.Contains(addr) {
						want = true
						break
					}
				}
			}
			k := flowKey{}
			k.dst, k.dstOK = parseAddr(ip)
			if got := owns(p.snapshot(), k); got != want {
				t.Fatalf("prefixes %v ip %q: reference=%v compiled=%v", list, ip, want, got)
			}
		}
	}
}

// A program replaced by Load must be matched against the new rules, not a stale
// compiled copy.
func TestLoadRecompilesRules(t *testing.T) {
	p := New(model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ASIC:     []model.ACLEntry{{Action: model.ActionDrop, RuleID: "old", Match: model.Match{SrcCIDR: "198.51.100.0/24"}}},
	})
	flow := model.Flow{SrcIP: "198.51.100.9", DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, PPS: 1}
	if d := p.Decide(flow); d.Action != model.ActionDrop || d.RuleID != "old" {
		t.Fatalf("expected the original rule to drop, got %+v", d)
	}
	// Swap in a program whose ACL covers a different source, and change prefixes.
	p.Load(model.Program{
		Prefixes: []string{"198.18.0.0/24"},
		ASIC:     []model.ACLEntry{{Action: model.ActionDrop, RuleID: "new", Match: model.Match{SrcCIDR: "203.0.113.0/24"}}},
	})
	if d := p.Decide(flow); d.Reason != "prefix not assigned to this node" {
		t.Fatalf("expected the new prefix list to apply, got %+v", d)
	}
	newFlow := model.Flow{SrcIP: "203.0.113.5", DstIP: "198.18.0.7", Proto: "tcp", DPort: 443, PPS: 1}
	if d := p.Decide(newFlow); d.Action != model.ActionDrop || d.RuleID != "new" {
		t.Fatalf("expected the new rule to drop, got %+v", d)
	}
}

// A rule with an unparseable CIDR must stay inert rather than matching
// everything, which is how it behaved when parsing happened per packet.
func TestRuleWithMalformedCIDRNeverMatches(t *testing.T) {
	p := New(model.Program{
		Prefixes: []string{"203.0.113.0/24"},
		ASIC: []model.ACLEntry{
			{Action: model.ActionDrop, RuleID: "broken", Match: model.Match{SrcCIDR: "203.0.113.0/99"}},
		},
	})
	d := p.Decide(model.Flow{SrcIP: "203.0.113.5", DstIP: "203.0.113.10", Proto: "tcp", DPort: 443, PPS: 1})
	if d.Action != model.ActionPermit {
		t.Fatalf("a rule with a malformed CIDR must not match: %+v", d)
	}
}

func TestDecideHandlesMalformedFlowAddresses(t *testing.T) {
	p := New(benchProgram())
	for _, f := range []model.Flow{
		{SrcIP: "", DstIP: "", Proto: "tcp", PPS: 1},
		{SrcIP: "bogus", DstIP: "203.0.113.10", Proto: "tcp", PPS: 1},
		{SrcIP: "203.0.113.5", DstIP: "bogus", Proto: "tcp", PPS: 1},
	} {
		d := p.Decide(f)
		if d.Action == "" || d.Stage == "" {
			t.Fatalf("flow %+v produced an empty decision %+v", f, d)
		}
	}
}
