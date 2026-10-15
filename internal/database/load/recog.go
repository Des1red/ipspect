package load

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"ipspect/internal/database"
	"strings"
	"sync"

	recog "github.com/runZeroInc/recog-go"
)

type RecogSourceInfo struct {
	Key      string
	File     string
	Protocol string
	Total    int
	Usable   int
	Skipped  int
}

var (
	recogOnce sync.Once
	recogErr  error

	recogDBs map[string]*recog.FingerprintDB

	recogCatalog []RecogSourceInfo
)

func LoadRecog() error {
	recogOnce.Do(func() {
		recogErr = loadRecog()
	})

	return recogErr
}

func loadRecog() error {
	filesystem, err := database.RecogFS()
	if err != nil {
		return fmt.Errorf(
			"access Recog assets: %w",
			err,
		)
	}

	entries, err := fs.ReadDir(
		filesystem,
		".",
	)

	if err != nil {
		return fmt.Errorf(
			"list Recog databases: %w",
			err,
		)
	}

	databases := make(
		map[string]*recog.FingerprintDB,
	)

	var catalog []RecogSourceInfo

	for _, entry := range entries {
		if entry.IsDir() ||
			!strings.HasSuffix(
				entry.Name(),
				".xml",
			) {

			continue
		}

		filename := entry.Name()

		data, err := fs.ReadFile(
			filesystem,
			filename,
		)

		if err != nil {
			return fmt.Errorf(
				"read Recog database %s: %w",
				filename,
				err,
			)
		}

		var db recog.FingerprintDB

		if err := xml.Unmarshal(
			data,
			&db,
		); err != nil {

			return fmt.Errorf(
				"parse Recog database %s: %w",
				filename,
				err,
			)
		}

		key := strings.TrimSpace(
			db.Matches,
		)

		// Some upstream Recog databases
		// do not declare a matches key.
		if key == "" {
			key = strings.TrimSuffix(
				filename,
				".xml",
			)
		}

		if _, exists := databases[key]; exists {
			return fmt.Errorf(
				"duplicate Recog database key %q",
				key,
			)
		}

		total := len(db.Fingerprints)

		compiled := make(
			[]*recog.Fingerprint,
			0,
			total,
		)

		for _, fp := range db.Fingerprints {
			if err := fp.Normalize(); err != nil {
				continue
			}

			compiled = append(
				compiled,
				fp,
			)
		}

		if len(compiled) == 0 {
			return fmt.Errorf(
				"no usable fingerprints in %s",
				filename,
			)
		}

		db.Matches = key
		db.Fingerprints = compiled
		db.Name = filename

		databases[key] = &db

		catalog = append(
			catalog,
			RecogSourceInfo{
				Key:      key,
				File:     filename,
				Protocol: db.Protocol,
				Total:    total,
				Usable:   len(compiled),
				Skipped:  total - len(compiled),
			},
		)
	}

	if len(databases) == 0 {
		return fmt.Errorf(
			"no Recog databases found",
		)
	}

	// Publish only after all databases
	// have loaded successfully.
	recogDBs = databases
	recogCatalog = catalog

	return nil
}

func RecogDB(
	key string,
) *recog.FingerprintDB {
	return recogDBs[key]
}

func RecogCatalog() []RecogSourceInfo {
	return append(
		[]RecogSourceInfo(nil),
		recogCatalog...,
	)
}
