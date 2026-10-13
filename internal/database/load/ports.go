package load

import (
	"encoding/csv"
	"fmt"
	"io"
	"ipspect/internal/database"
	"strconv"
	"strings"
	"sync"
)

var (
	portsOnce sync.Once
	portsErr  error

	portNames map[int]string
)

func LoadPorts() error {
	portsOnce.Do(func() {
		file, err := database.OpenPorts(
			"services.csv",
		)

		if err != nil {
			portsErr = fmt.Errorf(
				"open IANA services: %w",
				err,
			)
			return
		}

		defer file.Close()

		portNames, portsErr = parsePorts(
			file,
		)
	})

	return portsErr
}

func LookupPort(
	port int,
) string {
	if name, ok := portNames[port]; ok {
		return name
	}

	return "unknown"
}

func parsePorts(
	source io.Reader,
) (map[int]string, error) {
	reader := csv.NewReader(source)

	reader.FieldsPerRecord = -1

	header, err := reader.Read()

	if err != nil {
		return nil, fmt.Errorf(
			"read IANA CSV header: %w",
			err,
		)
	}

	columns := make(
		map[string]int,
	)

	for i, name := range header {
		name = strings.TrimSpace(name)

		name = strings.TrimPrefix(
			name,
			"\ufeff",
		)

		columns[name] = i
	}

	nameCol, ok := columns["Service Name"]

	if !ok {
		return nil, fmt.Errorf(
			"IANA CSV missing Service Name column",
		)
	}

	portCol, ok := columns["Port Number"]

	if !ok {
		return nil, fmt.Errorf(
			"IANA CSV missing Port Number column",
		)
	}

	protocolCol, ok :=
		columns["Transport Protocol"]

	if !ok {
		return nil, fmt.Errorf(
			"IANA CSV missing Transport Protocol column",
		)
	}

	services := make(
		map[int]string,
	)

	for {
		record, err := reader.Read()

		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, fmt.Errorf(
				"read IANA service record: %w",
				err,
			)
		}

		if nameCol >= len(record) ||
			portCol >= len(record) ||
			protocolCol >= len(record) {

			continue
		}

		protocol := strings.ToLower(
			strings.TrimSpace(
				record[protocolCol],
			),
		)

		if protocol != "tcp" {
			continue
		}

		name := strings.TrimSpace(
			record[nameCol],
		)

		if name == "" {
			continue
		}

		port, err := strconv.Atoi(
			strings.TrimSpace(
				record[portCol],
			),
		)

		if err != nil ||
			port < 1 ||
			port > 65535 {

			continue
		}

		if _, exists := services[port]; exists {
			continue
		}

		services[port] = name
	}

	if len(services) == 0 {
		return nil, fmt.Errorf(
			"IANA service database is empty",
		)
	}

	return services, nil
}
