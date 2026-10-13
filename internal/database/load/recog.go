package load

import (
	"encoding/xml"
	"fmt"
	"io"
	"ipspect/internal/database"
	"sync"

	recog "github.com/runZeroInc/recog-go"
)

type recogSource struct {
	key  string
	file string
}

var recogSources = []recogSource{
	{key: "ssh.banner", file: "ssh_banners.xml"},
	{key: "ftp.banner", file: "ftp_banners.xml"},
	{key: "smtp.banner", file: "smtp_banners.xml"},
	{key: "http_header.server", file: "http_servers.xml"},
}

var (
	recogOnce sync.Once
	recogErr  error
	recogDBs  map[string]*recog.FingerprintDB
)

func LoadRecog() error {
	recogOnce.Do(func() {
		recogDBs = make(
			map[string]*recog.FingerprintDB,
		)

		for _, source := range recogSources {
			file, err := database.OpenRecog(source.file)
			if err != nil {
				recogErr = fmt.Errorf(
					"open Recog database %s: %w",
					source.file,
					err,
				)
				return
			}

			data, err := io.ReadAll(file)
			file.Close()

			if err != nil {
				recogErr = fmt.Errorf(
					"read Recog database %s: %w",
					source.file,
					err,
				)
				return
			}

			var db recog.FingerprintDB

			if err := xml.Unmarshal(data, &db); err != nil {
				recogErr = fmt.Errorf(
					"parse Recog database %s: %w",
					source.file,
					err,
				)
				return
			}

			if db.Matches != source.key {
				recogErr = fmt.Errorf(
					"Recog database %s matches %q, expected %q",
					source.file,
					db.Matches,
					source.key,
				)
				return
			}

			compiled := make(
				[]*recog.Fingerprint,
				0,
				len(db.Fingerprints),
			)

			for _, fp := range db.Fingerprints {
				if fp.Normalize() == nil {
					compiled = append(compiled, fp)
				}
			}

			if len(compiled) == 0 {
				recogErr = fmt.Errorf(
					"no usable fingerprints in %s",
					source.file,
				)
				return
			}

			db.Fingerprints = compiled
			db.Name = source.file

			recogDBs[source.key] = &db
		}
	})

	return recogErr
}

func RecogDB(key string) *recog.FingerprintDB {
	return recogDBs[key]
}
