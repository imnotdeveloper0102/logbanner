// Package firewall applies and removes IP bans in the host firewall.
//
// Two drivers shell out to the host firewall tools. Arguments are
// always passed as separate argv entries, never through a shell, and
// only after the IP has been validated, so a log line can never
// become a shell command. The nftables driver is the default; the
// iptables driver uses ipset sets. A dry-run driver logs what would
// happen and touches nothing, and is what the agent uses until an
// operator turns dry-run off. Nothing in this package runs a
// firewall command at import time: a driver that cannot find its
// binary, or cannot set up its table/sets, fails loudly from New so
// the agent exits at startup instead of silently banning nothing.
package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
)

// Driver bans and unbans a single IP. A nil duration means a
// permanent ban; any other duration is seconds until the firewall
// itself drops the ban (the agent only records the expiry).
type Driver interface {
	Name() string
	Ban(ctx context.Context, ip net.IP, durationSeconds *int) error
	Unban(ctx context.Context, ip net.IP) error
}

// Runner executes a binary with argv entries. The default runs the
// real binary; tests substitute a recorder, so driver tests never
// touch the real firewall.
type Runner func(ctx context.Context, name string, args ...string) error

func execRunner(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// validateIP rejects anything that is not a single usable IP. Ban
// targets come from detections, which are single IPs, never CIDRs.
func validateIP(ip net.IP) (net.IP, error) {
	if ip == nil || ip.IsUnspecified() {
		return nil, fmt.Errorf("refusing to ban invalid IP %q", ip.String())
	}
	return ip, nil
}

// New builds the named driver and sets up its firewall state. An
// empty name means nftables. A missing binary or a failed setup is
// an error, not a silent fallback.
func New(name string) (Driver, error) {
	switch name {
	case "", "nftables":
		return NewNFTables("nft")
	case "iptables":
		return NewIPTables("ipset", "iptables", "ip6tables")
	default:
		return nil, fmt.Errorf("unknown firewall driver %q: want nftables or iptables", name)
	}
}

// DryRunDriver logs what would be banned or unbanned and changes
// nothing. It still validates IPs, so a bad detection fails the
// same way in dry-run as it would live.
type DryRunDriver struct {
	log      *slog.Logger
	banned   atomic.Uint64
	unbanned atomic.Uint64
}

// NewDryRun returns a Driver that only logs.
func NewDryRun(log *slog.Logger) *DryRunDriver {
	if log == nil {
		log = slog.Default()
	}
	return &DryRunDriver{log: log}
}

// Name returns "dry-run".
func (d *DryRunDriver) Name() string { return "dry-run" }

// Banned returns how many would-be bans were logged.
func (d *DryRunDriver) Banned() uint64 { return d.banned.Load() }

// Unbanned returns how many would-be unbans were logged.
func (d *DryRunDriver) Unbanned() uint64 { return d.unbanned.Load() }

// Ban logs "would ban <ip> for <duration>" and records nothing.
func (d *DryRunDriver) Ban(ctx context.Context, ip net.IP, durationSeconds *int) error {
	ip, err := validateIP(ip)
	if err != nil {
		return err
	}
	if durationSeconds == nil {
		d.log.Info("would ban (permanent)", "ip", ip.String())
	} else {
		d.log.Info("would ban", "ip", ip.String(), "duration_seconds", *durationSeconds)
	}
	d.banned.Add(1)
	return nil
}

// Unban logs "would unban <ip>" and records nothing.
func (d *DryRunDriver) Unban(ctx context.Context, ip net.IP) error {
	ip, err := validateIP(ip)
	if err != nil {
		return err
	}
	d.log.Info("would unban", "ip", ip.String())
	d.unbanned.Add(1)
	return nil
}

const (
	nftTable    = "logbanner"
	nftSetV4    = "logbanner_v4"
	nftSetV6    = "logbanner_v6"
	ipsetNameV4 = "logbanner_v4"
	ipsetNameV6 = "logbanner_v6"
)

// NFTablesDriver bans IPs by adding them to nftables sets with a
// timeout. The sets live in table "inet logbanner"; a chain drops
// input packets whose source is in the matching set. A set element
// added without a timeout is permanent. The firewall enforces the
// timeout itself, so a ban outlives an agent crash.
type NFTablesDriver struct {
	binary string
	run    Runner
}

// NewNFTables checks the nft binary exists and creates the table,
// chain, sets and drop rules (skipped when the table already
// exists, since they are created together).
func NewNFTables(binary string) (*NFTablesDriver, error) {
	if _, err := exec.LookPath(binary); err != nil {
		return nil, fmt.Errorf("nftables driver: %s binary not found in PATH: %w", binary, err)
	}
	d := &NFTablesDriver{binary: binary, run: execRunner}
	if err := d.Ensure(context.Background()); err != nil {
		return nil, err
	}
	return d, nil
}

// Name returns "nftables".
func (d *NFTablesDriver) Name() string { return "nftables" }

func nftSet(ip net.IP) string {
	if ip.To4() != nil {
		return nftSetV4
	}
	return nftSetV6
}

// Ensure creates the table, chain, sets and drop rules, unless the
// table already exists. If the table exists but the sets or rules
// were deleted by hand, delete the table and let the agent recreate
// it on the next start; partial setups are not repaired here.
func (d *NFTablesDriver) Ensure(ctx context.Context) error {
	if err := d.run(ctx, d.binary, "list", "table", "inet", nftTable); err == nil {
		return nil
	}
	steps := [][]string{
		{"add", "table", "inet", nftTable},
		{"add", "chain", "inet", nftTable, "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"},
		{"add", "set", "inet", nftTable, nftSetV4, "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}"},
		{"add", "set", "inet", nftTable, nftSetV6, "{", "type", "ipv6_addr", ";", "flags", "timeout", ";", "}"},
		{"add", "rule", "inet", nftTable, "input", "ip", "saddr", "@" + nftSetV4, "drop"},
		{"add", "rule", "inet", nftTable, "input", "ip6", "saddr", "@" + nftSetV6, "drop"},
	}
	for _, args := range steps {
		if err := d.run(ctx, d.binary, args...); err != nil {
			return fmt.Errorf("nftables setup: %w", err)
		}
	}
	return nil
}

// Ban adds the IP to the matching set, with a timeout when the ban
// expires and without one when it is permanent.
func (d *NFTablesDriver) Ban(ctx context.Context, ip net.IP, durationSeconds *int) error {
	ip, err := validateIP(ip)
	if err != nil {
		return err
	}
	args := []string{"add", "element", "inet", nftTable, nftSet(ip), "{", ip.String()}
	if durationSeconds != nil {
		args = append(args, "timeout", strconv.Itoa(*durationSeconds)+"s")
	}
	args = append(args, "}")
	return d.run(ctx, d.binary, args...)
}

// Unban removes the IP from the matching set. Deleting an element
// that is not there is an error from nft; the caller logs it and
// moves on, since the desired end state (IP not banned) already holds.
func (d *NFTablesDriver) Unban(ctx context.Context, ip net.IP) error {
	ip, err := validateIP(ip)
	if err != nil {
		return err
	}
	return d.run(ctx, d.binary, "delete", "element", "inet", nftTable, nftSet(ip), "{", ip.String(), "}")
}

// IPTablesDriver bans IPs with ipset sets (hash:ip, per-element
// timeout) and iptables/ip6tables rules that drop packets from the
// sets. A timeout of 0 is a permanent entry.
type IPTablesDriver struct {
	ipset, iptables, ip6tables string
	run                        Runner
}

// NewIPTables checks the ipset, iptables and ip6tables binaries
// exist and creates the sets and drop rules (idempotently).
func NewIPTables(ipset, iptables, ip6tables string) (*IPTablesDriver, error) {
	for _, bin := range []string{ipset, iptables, ip6tables} {
		if _, err := exec.LookPath(bin); err != nil {
			return nil, fmt.Errorf("iptables driver: %s binary not found in PATH: %w", bin, err)
		}
	}
	d := &IPTablesDriver{ipset: ipset, iptables: iptables, ip6tables: ip6tables, run: execRunner}
	if err := d.Ensure(context.Background()); err != nil {
		return nil, err
	}
	return d, nil
}

// Name returns "iptables".
func (d *IPTablesDriver) Name() string { return "iptables" }

func ipsetName(ip net.IP) string {
	if ip.To4() != nil {
		return ipsetNameV4
	}
	return ipsetNameV6
}

// Ensure creates both ipset sets (with -exist, so re-running is
// safe) and inserts the INPUT drop rules when they are not already
// there (checked with -C, which exits non-zero when the rule is
// missing).
func (d *IPTablesDriver) Ensure(ctx context.Context) error {
	steps := [][]string{
		{d.ipset, "create", ipsetNameV4, "hash:ip", "timeout", "0", "-exist"},
		{d.ipset, "create", ipsetNameV6, "hash:ip", "family", "inet6", "timeout", "0", "-exist"},
	}
	for _, args := range steps {
		if err := d.run(ctx, args[0], args[1:]...); err != nil {
			return fmt.Errorf("iptables setup: %w", err)
		}
	}
	rules := []struct {
		binary string
		set    string
	}{
		{d.iptables, ipsetNameV4},
		{d.ip6tables, ipsetNameV6},
	}
	for _, r := range rules {
		check := []string{"-C", "INPUT", "-m", "set", "--match-set", r.set, "src", "-j", "DROP"}
		if err := d.run(ctx, r.binary, check...); err == nil {
			continue
		}
		insert := []string{"-I", "INPUT", "-m", "set", "--match-set", r.set, "src", "-j", "DROP"}
		if err := d.run(ctx, r.binary, insert...); err != nil {
			return fmt.Errorf("iptables setup: %w", err)
		}
	}
	return nil
}

// Ban adds the IP to the matching ipset with the ban length as its
// timeout, or timeout 0 for a permanent ban.
func (d *IPTablesDriver) Ban(ctx context.Context, ip net.IP, durationSeconds *int) error {
	ip, err := validateIP(ip)
	if err != nil {
		return err
	}
	timeout := "0"
	if durationSeconds != nil {
		timeout = strconv.Itoa(*durationSeconds)
	}
	return d.run(ctx, d.ipset, "add", ipsetName(ip), ip.String(), "timeout", timeout, "-exist")
}

// Unban removes the IP from the matching ipset.
func (d *IPTablesDriver) Unban(ctx context.Context, ip net.IP) error {
	ip, err := validateIP(ip)
	if err != nil {
		return err
	}
	return d.run(ctx, d.ipset, "del", ipsetName(ip), ip.String(), "-exist")
}
