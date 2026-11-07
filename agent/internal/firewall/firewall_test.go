package firewall

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
)

// recorder captures every command a driver would run, so tests
// assert on argv construction without ever touching the real
// firewall. failOn, when set, makes calls whose first argument
// matches fail, which is how the Ensure tests simulate a missing
// table or rule.
type recorder struct {
	calls  []call
	failOn string
}

type call struct {
	name string
	args []string
}

func (r *recorder) run(ctx context.Context, name string, args ...string) error {
	r.calls = append(r.calls, call{name, append([]string(nil), args...)})
	if r.failOn != "" && len(args) > 0 && args[0] == r.failOn {
		return errFake
	}
	return nil
}

type fakeError string

func (e fakeError) Error() string { return string(e) }

const errFake fakeError = "simulated failure"

func intPtr(n int) *int { return &n }

func TestNFTablesBanArgs(t *testing.T) {
	r := &recorder{}
	d := &NFTablesDriver{binary: "nft", run: r.run}
	ctx := context.Background()

	if err := d.Ban(ctx, net.ParseIP("203.0.113.5"), intPtr(3600)); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	want := []string{"add", "element", "inet", "logbanner", "logbanner_v4", "{", "203.0.113.5", "timeout", "3600s", "}"}
	if !reflect.DeepEqual(r.calls[0].args, want) {
		t.Errorf("timed ban argv = %v, want %v", r.calls[0].args, want)
	}

	if err := d.Ban(ctx, net.ParseIP("203.0.113.5"), nil); err != nil {
		t.Fatalf("permanent Ban: %v", err)
	}
	want = []string{"add", "element", "inet", "logbanner", "logbanner_v4", "{", "203.0.113.5", "}"}
	if !reflect.DeepEqual(r.calls[1].args, want) {
		t.Errorf("permanent ban argv = %v, want %v", r.calls[1].args, want)
	}

	if err := d.Ban(ctx, net.ParseIP("2001:db8::1"), intPtr(600)); err != nil {
		t.Fatalf("IPv6 Ban: %v", err)
	}
	want = []string{"add", "element", "inet", "logbanner", "logbanner_v6", "{", "2001:db8::1", "timeout", "600s", "}"}
	if !reflect.DeepEqual(r.calls[2].args, want) {
		t.Errorf("IPv6 ban argv = %v, want %v", r.calls[2].args, want)
	}

	if err := d.Unban(ctx, net.ParseIP("203.0.113.5")); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	want = []string{"delete", "element", "inet", "logbanner", "logbanner_v4", "{", "203.0.113.5", "}"}
	if !reflect.DeepEqual(r.calls[3].args, want) {
		t.Errorf("unban argv = %v, want %v", r.calls[3].args, want)
	}
	if err := d.Unban(ctx, net.ParseIP("2001:db8::1")); err != nil {
		t.Fatalf("IPv6 Unban: %v", err)
	}
	if r.calls[4].args[4] != "logbanner_v6" {
		t.Errorf("IPv6 unban used set %q, want logbanner_v6", r.calls[4].args[4])
	}
}

func TestNFTablesEnsure(t *testing.T) {
	// Table missing: list fails, all six setup steps run.
	r := &recorder{failOn: "list"}
	d := &NFTablesDriver{binary: "nft", run: r.run}
	if err := d.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if len(r.calls) != 7 {
		t.Fatalf("Ensure made %d calls, want 7 (list + 6 setup steps)", len(r.calls))
	}
	if r.calls[1].args[0] != "add" || r.calls[1].args[1] != "table" {
		t.Errorf("first setup step = %v, want add table", r.calls[1].args)
	}
	chain := r.calls[2].args
	if !strings.Contains(strings.Join(chain, " "), "type filter hook input") {
		t.Errorf("chain step = %v, want a filter input chain", chain)
	}
	if got := r.calls[5].args; !reflect.DeepEqual(got, []string{"add", "rule", "inet", "logbanner", "input", "ip", "saddr", "@logbanner_v4", "drop"}) {
		t.Errorf("IPv4 drop rule = %v", got)
	}
	if got := r.calls[6].args; !reflect.DeepEqual(got, []string{"add", "rule", "inet", "logbanner", "input", "ip6", "saddr", "@logbanner_v6", "drop"}) {
		t.Errorf("IPv6 drop rule = %v", got)
	}

	// Table already exists: list succeeds, nothing else runs.
	r = &recorder{}
	d = &NFTablesDriver{binary: "nft", run: r.run}
	if err := d.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure with existing table: %v", err)
	}
	if len(r.calls) != 1 {
		t.Errorf("Ensure with existing table made %d calls, want 1", len(r.calls))
	}
}

func TestIPTablesBanArgs(t *testing.T) {
	r := &recorder{}
	d := &IPTablesDriver{ipset: "ipset", iptables: "iptables", ip6tables: "ip6tables", run: r.run}
	ctx := context.Background()

	if err := d.Ban(ctx, net.ParseIP("203.0.113.5"), intPtr(3600)); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	want := []string{"add", "logbanner_v4", "203.0.113.5", "timeout", "3600", "-exist"}
	if !reflect.DeepEqual(r.calls[0].args, want) || r.calls[0].name != "ipset" {
		t.Errorf("timed ban = %s %v, want ipset %v", r.calls[0].name, r.calls[0].args, want)
	}

	if err := d.Ban(ctx, net.ParseIP("2001:db8::1"), nil); err != nil {
		t.Fatalf("permanent IPv6 Ban: %v", err)
	}
	want = []string{"add", "logbanner_v6", "2001:db8::1", "timeout", "0", "-exist"}
	if !reflect.DeepEqual(r.calls[1].args, want) {
		t.Errorf("permanent IPv6 ban argv = %v, want %v", r.calls[1].args, want)
	}

	if err := d.Unban(ctx, net.ParseIP("203.0.113.5")); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	want = []string{"del", "logbanner_v4", "203.0.113.5", "-exist"}
	if !reflect.DeepEqual(r.calls[2].args, want) {
		t.Errorf("unban argv = %v, want %v", r.calls[2].args, want)
	}
}

func TestIPTablesEnsure(t *testing.T) {
	// -C checks fail (rules missing), so both rules are inserted.
	r := &recorder{failOn: "-C"}
	d := &IPTablesDriver{ipset: "ipset", iptables: "iptables", ip6tables: "ip6tables", run: r.run}
	if err := d.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	var inserts []call
	for _, c := range r.calls {
		if len(c.args) > 0 && c.args[0] == "-I" {
			inserts = append(inserts, c)
		}
	}
	if len(inserts) != 2 {
		t.Fatalf("Ensure inserted %d rules, want 2 (IPv4 + IPv6)", len(inserts))
	}
	if inserts[0].name != "iptables" || inserts[1].name != "ip6tables" {
		t.Errorf("inserts went to %q and %q, want iptables and ip6tables", inserts[0].name, inserts[1].name)
	}
	if r.calls[1].args[3] != "family" || r.calls[1].args[4] != "inet6" {
		t.Errorf("IPv6 set creation = %v, want family inet6", r.calls[1].args)
	}

	// Rules already there: -C succeeds, no -I runs.
	r = &recorder{}
	d = &IPTablesDriver{ipset: "ipset", iptables: "iptables", ip6tables: "ip6tables", run: r.run}
	if err := d.Ensure(context.Background()); err != nil {
		t.Fatalf("Ensure with existing rules: %v", err)
	}
	for _, c := range r.calls {
		if len(c.args) > 0 && c.args[0] == "-I" {
			t.Errorf("Ensure inserted a rule that already exists: %v", c.args)
		}
	}
}

func TestDriversRejectInvalidIP(t *testing.T) {
	ctx := context.Background()
	drivers := []Driver{
		&NFTablesDriver{binary: "nft", run: (&recorder{}).run},
		&IPTablesDriver{ipset: "ipset", iptables: "iptables", ip6tables: "ip6tables", run: (&recorder{}).run},
		NewDryRun(nil),
	}
	for _, d := range drivers {
		for _, ip := range []net.IP{nil, net.ParseIP("0.0.0.0"), net.ParseIP("::")} {
			if err := d.Ban(ctx, ip, intPtr(60)); err == nil {
				t.Errorf("%s Ban accepted invalid IP %v", d.Name(), ip)
			}
			if err := d.Unban(ctx, ip); err == nil {
				t.Errorf("%s Unban accepted invalid IP %v", d.Name(), ip)
			}
		}
	}
}

func TestNewUnknownDriver(t *testing.T) {
	if _, err := New("pf"); err == nil {
		t.Error("New accepted unknown driver \"pf\"")
	}
}

func TestNewMissingBinaryFailsLoudly(t *testing.T) {
	if _, err := NewNFTables("definitely-not-a-real-binary"); err == nil {
		t.Error("NewNFTables accepted a missing binary")
	}
	if _, err := NewIPTables("definitely-not-a-real-binary", "iptables", "ip6tables"); err == nil {
		t.Error("NewIPTables accepted a missing ipset binary")
	}
}

func TestDryRunDriver(t *testing.T) {
	d := NewDryRun(nil)
	ctx := context.Background()
	if d.Name() != "dry-run" {
		t.Errorf("Name = %q, want dry-run", d.Name())
	}
	if err := d.Ban(ctx, net.ParseIP("203.0.113.5"), intPtr(3600)); err != nil {
		t.Fatalf("dry-run Ban: %v", err)
	}
	if err := d.Ban(ctx, net.ParseIP("2001:db8::1"), nil); err != nil {
		t.Fatalf("dry-run permanent Ban: %v", err)
	}
	if err := d.Unban(ctx, net.ParseIP("203.0.113.5")); err != nil {
		t.Fatalf("dry-run Unban: %v", err)
	}
	if d.Banned() != 2 || d.Unbanned() != 1 {
		t.Errorf("dry-run counts: banned %d unbanned %d, want 2 and 1", d.Banned(), d.Unbanned())
	}
}
