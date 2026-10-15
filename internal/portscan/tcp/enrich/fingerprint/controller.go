package fingerprint

import (
	"fmt"
	"ipspect/internal/database/load"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"sync"
)

const fingerprintWorkers = 32

type fingerprintJob struct {
	hostIndex   int
	detailIndex int
}

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

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.fingerprint: starting %d workers",
			fingerprintWorkers,
		),
	)

	jobs := make(
		chan fingerprintJob,
		fingerprintWorkers,
	)

	var wg sync.WaitGroup

	for i := 0; i < fingerprintWorkers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for job := range jobs {
				host := &models.LOOT.Hosts[job.hostIndex]

				inspect(
					host.Target,
					&host.Details[job.detailIndex],
				)
			}
		}()
	}

	queued := 0

	for h := range models.LOOT.Hosts {
		host := &models.LOOT.Hosts[h]

		for i := range host.Details {
			if host.Details[i].State != "open" {
				continue
			}

			jobs <- fingerprintJob{
				hostIndex:   h,
				detailIndex: i,
			}

			queued++
		}
	}

	output.Log(
		"debug",
		fmt.Sprintf(
			"tcp.fingerprint: queued %d open ports",
			queued,
		),
	)

	close(jobs)
	wg.Wait()

	output.Log(
		"debug",
		"tcp.fingerprint: all workers completed",
	)

	return nil
}
