package identity

import "testing"

func TestParseCableName(t *testing.T) {
	good := []string{"Arman_Films", "abc", "My.Channel-1", "Tech4U"}
	for _, g := range good {
		if _, _, err := ParseCableName(g); err != nil {
			t.Errorf("%q should be valid: %v", g, err)
		}
	}
	bad := map[string]error{
		"ab":             ErrLength,
		"123456789":      ErrAllDigits,
		"bad name":       ErrChars,
		"_abc":           ErrEdges,
		"abc-":           ErrEdges,
		"a..b":           ErrEdges,
		"ZEAIPC":         ErrReserved,
		"Z3A1PC":         ErrReserved,
		"zeaipc-support": ErrReserved,
		"Zikriyon_OS":    ErrReserved,
		"Zikriy0nAI":     ErrReserved,
		"Admin":          ErrReserved,
		"Fyber.Flix":     ErrReserved,
	}
	for in, want := range bad {
		if _, _, err := ParseCableName(in); err != want {
			t.Errorf("%q: got %v want %v", in, err, want)
		}
	}
}

func TestNumbers(t *testing.T) {
	c, err := Candidates(10)
	if err != nil || len(c) != 10 {
		t.Fatal(err, len(c))
	}
	for _, n := range c {
		if len(n) != 9 || n[0] == '0' || n <= "109999999" || IsVanity(n) {
			t.Errorf("bad number %s", n)
		}
	}
	if !IsVanity("123456789") || !IsVanity("511111234") || IsVanity("538201947") {
		t.Fatal("vanity rule wrong")
	}
}
