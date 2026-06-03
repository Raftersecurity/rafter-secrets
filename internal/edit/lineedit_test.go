package edit

import "testing"

func TestDotenvEditor(t *testing.T) {
	e := lineEditor{keyOf: dotenvKeyOf, render: dotenvRender}
	orig := []byte("# comment\nAPI_KEY=old123\nDB_PASS=\"hunter2\"\n")

	got, err := e.apply(orig, opRotate, "API_KEY", "new456", 2)
	if err != nil {
		t.Fatal(err)
	}
	if want := "# comment\nAPI_KEY=new456\nDB_PASS=\"hunter2\"\n"; string(got) != want {
		t.Errorf("rotate:\n got %q\nwant %q", got, want)
	}

	got, _ = e.apply(orig, opRemove, "API_KEY", "", 2)
	if want := "# comment\nDB_PASS=\"hunter2\"\n"; string(got) != want {
		t.Errorf("remove:\n got %q\nwant %q", got, want)
	}

	got, _ = e.apply(orig, opAdd, "NEW_KEY", "val", 0)
	if want := "# comment\nAPI_KEY=old123\nDB_PASS=\"hunter2\"\nNEW_KEY=val\n"; string(got) != want {
		t.Errorf("add:\n got %q\nwant %q", got, want)
	}

	if _, err := e.apply(orig, opRotate, "MISSING", "x", 0); err != errKeyNotFound {
		t.Errorf("rotate missing: want errKeyNotFound, got %v", err)
	}
	if _, err := e.apply(orig, opAdd, "API_KEY", "x", 0); err != errKeyExists {
		t.Errorf("add existing: want errKeyExists, got %v", err)
	}
}

func TestShellEditorQuotesSafely(t *testing.T) {
	e := lineEditor{keyOf: shellKeyOf, render: shellRender}
	orig := []byte("export GITHUB_TOKEN=ghp_old\n")
	// A value containing shell metacharacters must come out single-quoted/inert.
	got, err := e.apply(orig, opRotate, "GITHUB_TOKEN", "ghp_$(rm -rf ~)`whoami`", 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := "export GITHUB_TOKEN='ghp_$(rm -rf ~)`whoami`'\n"; string(got) != want {
		t.Errorf("shell rotate:\n got %q\nwant %q", got, want)
	}
	// A value with a single quote can't round-trip our scanner → rejected.
	if _, err := e.apply(orig, opRotate, "GITHUB_TOKEN", "a'b", 1); err != errUnrepresentable {
		t.Errorf("single-quote value: want errUnrepresentable, got %v", err)
	}
}

func TestEncoderRejectsNewline(t *testing.T) {
	for name, r := range map[string]func(string, string) (string, error){
		"dotenv": dotenvRender, "shell": shellRender, "npmrc": npmrcRender,
	} {
		if _, err := r("K", "line1\nline2"); err != errUnrepresentable {
			t.Errorf("%s: newline value should be unrepresentable, got %v", name, err)
		}
	}
}

func TestDotenvQuotingChoice(t *testing.T) {
	cases := map[string]string{
		"plain":     "KEY=plain",
		"has space": `KEY="has space"`,
		`has"quote`: `KEY='has"quote'`,
	}
	for val, want := range cases {
		got, err := dotenvRender("KEY", val)
		if err != nil {
			t.Fatalf("%q: %v", val, err)
		}
		if got != want {
			t.Errorf("dotenvRender(%q) = %q, want %q", val, got, want)
		}
	}
	// both quote types present → unrepresentable
	if _, err := dotenvRender("K", `a"b'c`); err != errUnrepresentable {
		t.Errorf("both quotes: want errUnrepresentable, got %v", err)
	}
}
