package load

import "testing"

func TestLoadRecog(t *testing.T) {
	if err := LoadRecog(); err != nil {
		t.Fatal(err)
	}

	required := []string{
		"ssh.banner",
		"ftp.banner",
		"smtp.banner",
		"http_header.server",
		"telnet_banners",
	}

	for _, key := range required {
		db := RecogDB(key)

		if db == nil {
			t.Fatalf(
				"missing Recog database: %s",
				key,
			)
		}

		if len(db.Fingerprints) == 0 {
			t.Fatalf(
				"empty Recog database: %s",
				key,
			)
		}
	}
}

func TestRecogCatalog(t *testing.T) {
	if err := LoadRecog(); err != nil {
		t.Fatal(err)
	}

	catalog := RecogCatalog()

	if len(catalog) < 5 {
		t.Fatalf(
			"expected at least 5 databases, got %d",
			len(catalog),
		)
	}

	for _, source := range catalog {
		if source.Total !=
			source.Usable+source.Skipped {

			t.Fatalf(
				"invalid fingerprint counts in %s",
				source.File,
			)
		}

		if source.Usable == 0 {
			t.Fatalf(
				"no usable fingerprints in %s",
				source.File,
			)
		}
	}
}

func TestTelnetDatabaseMatch(t *testing.T) {
	if err := LoadRecog(); err != nil {
		t.Fatal(err)
	}

	db := RecogDB(
		"telnet_banners",
	)

	if db == nil {
		t.Fatal("Telnet database not loaded")
	}

	result := db.MatchFirst(
		"MikroTik v5.2\r\nLogin:",
	)

	if result == nil ||
		!result.Matched {

		t.Fatal("expected MikroTik match")
	}

	if result.Values["os.product"] != "RouterOS" {
		t.Fatalf(
			"unexpected OS product: %q",
			result.Values["os.product"],
		)
	}
}
