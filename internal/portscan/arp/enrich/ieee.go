package enrich

import (
	"embed"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

//go:embed data/*.csv
var ieeeFiles embed.FS

var (
	ieeeOnce    sync.Once
	ieeeErr     error
	ieeeVendors map[string]string
)

func loadIEEE() error {
	ieeeOnce.Do(func() {
		ieeeVendors = make(map[string]string)

		sources := []struct {
			path   string
			digits int
		}{
			{"data/oui.csv", 6},
			{"data/mam.csv", 7},
			{"data/oui36.csv", 9},
		}

		for _, source := range sources {
			file, err := ieeeFiles.Open(source.path)

			if err != nil {
				ieeeErr = err
				return
			}

			reader := csv.NewReader(file)
			reader.FieldsPerRecord = -1

			for {
				record, err := reader.Read()

				if err == io.EOF {
					break
				}

				if err != nil {
					ieeeErr = fmt.Errorf(
						"read IEEE %s: %w",
						source.path,
						err,
					)
					break
				}

				if len(record) < 3 {
					continue
				}

				assignment := strings.ToUpper(
					strings.TrimSpace(record[1]),
				)

				vendor := strings.TrimSpace(
					record[2],
				)

				if len(assignment) != source.digits ||
					vendor == "" {
					continue
				}

				if strings.ContainsAny(
					assignment,
					"-: ",
				) {
					continue
				}

				ieeeVendors[assignment] = vendor
			}

			file.Close()

			if ieeeErr != nil {
				return
			}
		}

		if len(ieeeVendors) == 0 {
			ieeeErr = fmt.Errorf(
				"IEEE vendor registries contain no entries",
			)
		}
	})

	return ieeeErr
}

func lookupVendor(value string) string {
	mac, err := net.ParseMAC(value)

	if err != nil || len(mac) != 6 {
		return "Unknown"
	}

	if mac[0]&1 != 0 {
		return "Multicast"
	}

	if mac[0]&2 != 0 {
		return "Locally administered"
	}

	key := strings.ToUpper(
		strings.ReplaceAll(
			mac.String(),
			":",
			"",
		),
	)

	for _, prefix := range []int{9, 7, 6} {
		if vendor, ok := ieeeVendors[key[:prefix]]; ok {
			return vendor
		}
	}

	return "Unknown"
}
