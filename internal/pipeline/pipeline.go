package pipeline

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

type Pipeline struct {
	mu      sync.Mutex
	program model.Program
	buckets map[string]int
}

func New(p model.Program) *Pipeline {
	return &Pipeline{program: p, buckets: map[string]int{}}
}

func (p *Pipeline) Load(prog model.Program) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.program = prog
	p.buckets = map[string]int{}
}

func (p *Pipeline) Decide(f model.Flow) model.Decision {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.owns(f.DstIP) && len(p.program.Prefixes) > 0 {
		return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "prefix not assigned to this node"}
	}
	for _, acl := range p.program.ASIC {
		if match(acl.Match, f) && acl.Action == model.ActionDrop {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageASIC, RuleID: acl.RuleID, Reason: "TCAM ACL drop"}
		}
	}
	for _, row := range p.program.FPGA {
		if !match(row.Match, f) {
			continue
		}
		if row.Action == model.ActionDrop {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.RuleID, Reason: "FPGA drop"}
		}
		if row.Meter > 0 && f.PPS > row.Meter {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageFPGA, RuleID: row.RuleID, Reason: fmt.Sprintf("FPGA meter %d pps exceeded", row.Meter)}
		}
	}
	for _, zc := range p.program.ZC {
		if !match(zc.Match, f) {
			continue
		}
		key := zc.RuleID + "|" + f.SrcIP
		p.buckets[key] += f.PPS
		if zc.PPS > 0 && p.buckets[key] > zc.PPS {
			return model.Decision{Action: model.ActionDrop, Stage: model.StageZC, RuleID: zc.RuleID, Reason: "PF_RING ZC behavioral cap"}
		}
		return model.Decision{Action: model.ActionPermit, Stage: model.StageZC, RuleID: zc.RuleID, Reason: "PF_RING ZC inspect pass"}
	}
	return model.Decision{Action: model.ActionPermit, Stage: model.StageASIC, Reason: "no matching drop rule"}
}

func (p *Pipeline) owns(dst string) bool {
	ip, err := netip.ParseAddr(dst)
	if err != nil {
		return false
	}
	for _, cidr := range p.program.Prefixes {
		pfx, err := netip.ParsePrefix(cidr)
		if err == nil && pfx.Contains(ip) {
			return true
		}
	}
	return false
}

func match(m model.Match, f model.Flow) bool {
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

func contains(cidr, ip string) bool {
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
