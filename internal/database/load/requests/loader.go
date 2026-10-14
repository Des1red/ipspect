package requests

import (
	"fmt"
	"io/fs"
	"ipspect/internal/database"
	"ipspect/internal/models"
	"sync"
)

var (
	requestsOnce sync.Once
	requestsErr  error
	requestsDB   []Probe
)

func Load() error {
	requestsOnce.Do(func() {
		assets, err := database.RequestFS()

		if err != nil {
			requestsErr = err
			return
		}

		names, err := fs.Glob(
			assets,
			"*.yaml",
		)

		if err != nil {
			requestsErr = err
			return
		}

		for _, name := range names {
			data, err := fs.ReadFile(
				assets,
				name,
			)

			if err != nil {
				requestsErr = fmt.Errorf(
					"read request template %s: %w",
					name,
					err,
				)
				return
			}

			probes := parseRequestTemplate(data)

			requestsDB = append(
				requestsDB,
				probes...,
			)
		}

		if len(requestsDB) == 0 {
			requestsErr = fmt.Errorf(
				"no compatible TCP detection templates found",
			)
		}
	})

	return requestsErr
}

func ForPort(
	port int,
) []Probe {
	return ForEvidence(
		models.NucleiSearch{
			Port: port,
		},
	)
}

func matchesPort(
	probe Probe,
	port int,
) bool {
	for _, suggested := range probe.Ports {
		if suggested == port {
			return true
		}
	}

	return false
}

func Count() int {
	return len(requestsDB)
}
