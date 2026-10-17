// Package bgp renders an announcement plan as commands for a BGP speaker.
//
// Scrubline does not speak BGP itself. It compiles the plan, the same way it
// compiles TCAM, FPGA, and ZC programs, and the node agent hands it to the
// speaker running beside it. ExaBGP's text interface is what is rendered here
// because it is a line protocol that can be read, diffed, and tested; the plan
// is also served as JSON for anything that prefers to drive its own speaker.
package bgp

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/Jacksondude1223-bit/scrubline-cloud-scrub/internal/model"
)

// wellKnownCommunities are the named values a speaker understands directly.
var wellKnownCommunities = map[string]bool{
	"no-export":           true,
	"no-advertise":        true,
	"no-export-subconfed": true,
	"blackhole":           true,
}

// ValidateCommunity checks one community string.
//
// These reach the agent from a policy and are written into a routing daemon's
// control pipe, so an unchecked value is a command injection into the thing
// that decides where the internet sends traffic. Only the standard forms are
// accepted; anything else is refused rather than quoted.
func ValidateCommunity(c string) error {
	if c == "" {
		return fmt.Errorf("community must not be empty")
	}
	if wellKnownCommunities[strings.ToLower(c)] {
		return nil
	}
	parts := strings.Split(c, ":")
	switch len(parts) {
	case 2:
		// Standard community: two 16-bit halves.
		for _, p := range parts {
			if err := numericPart(p, 65535); err != nil {
				return fmt.Errorf("community %q: %w", c, err)
			}
		}
		return nil
	case 3:
		// Large community: three 32-bit values.
		for _, p := range parts {
			if err := numericPart(p, 4294967295); err != nil {
				return fmt.Errorf("community %q: %w", c, err)
			}
		}
		return nil
	}
	return fmt.Errorf("community %q is not a known name, ASN:value, or ASN:value:value", c)
}

func numericPart(p string, max uint64) error {
	if p == "" {
		return fmt.Errorf("empty component")
	}
	v, err := strconv.ParseUint(p, 10, 64)
	if err != nil {
		return fmt.Errorf("component %q is not a number", p)
	}
	if v > max {
		return fmt.Errorf("component %q is above %d", p, max)
	}
	return nil
}

// Commands renders the plan as ExaBGP commands, one per line, sorted so an
// unchanged plan renders byte for byte the same and the agent can tell when
// nothing moved.
//
// localAS is the AS the speaker announces from. It is only needed to pad the
// AS path; with localAS zero the padding is left out and the speaker's own
// configuration decides the path, so a plan that wanted prepends is reported
// as an error rather than silently announced at full preference.
func Commands(plan []model.Announcement, localAS int) ([]string, error) {
	if localAS < 0 || localAS > 4294967295 {
		return nil, fmt.Errorf("local AS %d is out of range", localAS)
	}
	rows := make([]model.Announcement, len(plan))
	copy(rows, plan)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Prefix != rows[j].Prefix {
			return rows[i].Prefix < rows[j].Prefix
		}
		return rows[i].NodeID < rows[j].NodeID
	})

	out := make([]string, 0, len(rows))
	for _, a := range rows {
		line, err := command(a, localAS)
		if err != nil {
			return nil, err
		}
		out = append(out, line)
	}
	return out, nil
}

func command(a model.Announcement, localAS int) (string, error) {
	if _, err := netip.ParsePrefix(a.Prefix); err != nil {
		return "", fmt.Errorf("announcement for %q: %v", a.Prefix, err)
	}

	var b strings.Builder
	switch a.State {
	case model.StateWithdraw:
		b.WriteString("withdraw route ")
	case model.StateAnnounce:
		b.WriteString("announce route ")
	default:
		return "", fmt.Errorf("announcement for %s: unknown state %q", a.Prefix, a.State)
	}
	b.WriteString(a.Prefix)

	if a.NextHop != "" {
		if _, err := netip.ParseAddr(a.NextHop); err != nil {
			return "", fmt.Errorf("announcement for %s: next hop %q: %v", a.Prefix, a.NextHop, err)
		}
		b.WriteString(" next-hop ")
		b.WriteString(a.NextHop)
	}

	// A withdrawal carries no attributes: the speaker only needs to know which
	// route to pull.
	if a.State == model.StateWithdraw {
		return b.String(), nil
	}

	if a.Prepends < 0 {
		return "", fmt.Errorf("announcement for %s: negative prepends", a.Prefix)
	}
	if a.Prepends > 0 {
		if localAS == 0 {
			return "", fmt.Errorf("announcement for %s asks for %d prepends but no local AS is configured", a.Prefix, a.Prepends)
		}
		as := strconv.Itoa(localAS)
		path := make([]string, 0, a.Prepends+1)
		for i := 0; i <= a.Prepends; i++ {
			path = append(path, as)
		}
		b.WriteString(" as-path [ ")
		b.WriteString(strings.Join(path, " "))
		b.WriteString(" ]")
	}

	if len(a.Communities) > 0 {
		for _, c := range a.Communities {
			if err := ValidateCommunity(c); err != nil {
				return "", fmt.Errorf("announcement for %s: %v", a.Prefix, err)
			}
		}
		b.WriteString(" community [ ")
		b.WriteString(strings.Join(a.Communities, " "))
		b.WriteString(" ]")
	}
	return b.String(), nil
}
