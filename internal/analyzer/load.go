package analyzer

import (
	"fmt"
	"ipspect/internal/database/load"
	"ipspect/internal/database/load/requests"
)

func Load() error {
	if err := load.LoadPorts(); err != nil {
		return fmt.Errorf("load IANA ports: %w", err)
	}

	if err := load.LoadRecog(); err != nil {
		return fmt.Errorf("load Recog: %w", err)
	}

	if err := requests.Load(); err != nil {
		return fmt.Errorf("load Nuclei: %w", err)
	}

	if err := load.LoadIEEE(); err != nil {
		return fmt.Errorf("load IEEE vendors: %w", err)
	}

	return nil
}
