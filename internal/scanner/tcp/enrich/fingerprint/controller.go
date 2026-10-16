package fingerprint

import (
	"fmt"
	"ipspect/internal/database/load"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/output"
)

func Controller() error {
	output.Log(
		"debug",
		"tcp.fingerprint: loading Recog databases",
	)

	if err := load.LoadRecog(); err != nil {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.fingerprint: Recog loading failed: %v",
				err,
			),
		)

		return err
	}

	catalog := load.RecogCatalog()

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.fingerprint: loaded %d Recog databases",
			len(catalog),
		),
	)

	for _, source := range catalog {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.fingerprint: Recog database key=%q file=%q signatures=%d skipped=%d",
				source.Key,
				source.File,
				source.Usable,
				source.Skipped,
			),
		)
	}

	output.Log(
		"debug",
		"tcp.fingerprint: loading Nuclei requests",
	)

	if err := requests.Load(); err != nil {
		output.Log(
			"debug",
			fmt.Sprintf(
				"tcp.fingerprint: Nuclei loading failed: %v",
				err,
			),
		)

		return err
	}

	output.Log(
		"debug",
		"tcp.fingerprint: Nuclei requests loaded",
	)

	runFingerprintWorkers()

	return nil
}
