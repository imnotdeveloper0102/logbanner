package rules

import "testing"

func intPtr(n int) *int { return &n }

func TestBanDuration(t *testing.T) {
	r := Rule{
		Name: "ssh-brute-force", BanSeconds: 3600,
		Escalation: []*int{intPtr(3600), intPtr(14400), intPtr(86400), nil},
	}
	cases := []struct {
		offence int
		want    *int // nil means permanent
	}{
		{1, intPtr(3600)},
		{2, intPtr(3600)},
		{3, intPtr(14400)},
		{4, intPtr(86400)},
		{5, nil},
		{6, nil},  // past the end keeps the last step (permanent)
		{10, nil}, // same, no matter how many offences follow
		{0, intPtr(3600)},
	}
	for _, c := range cases {
		got := r.BanDuration(c.offence)
		if c.want == nil {
			if got != nil {
				t.Errorf("offence %d: got %d seconds, want permanent (nil)", c.offence, *got)
			}
			continue
		}
		if got == nil {
			t.Errorf("offence %d: got permanent, want %d seconds", c.offence, *c.want)
			continue
		}
		if *got != *c.want {
			t.Errorf("offence %d: got %d seconds, want %d", c.offence, *got, *c.want)
		}
	}
}

func TestBanDurationWithoutEscalation(t *testing.T) {
	r := Rule{Name: "plain", BanSeconds: 600}
	for _, offence := range []int{1, 2, 5} {
		got := r.BanDuration(offence)
		if got == nil || *got != 600 {
			t.Errorf("offence %d without escalation: got %v, want 600", offence, got)
		}
	}
}
