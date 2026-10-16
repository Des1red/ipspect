package fingerprint

import (
	"fmt"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"ipspect/internal/scanner/tcp/enrich/fingerprint/flow"
	"sync"
)

const fingerprintWorkers = 32

type fingerprintJob struct {
	hostIndex   int
	detailIndex int
}

func runFingerprintWorkers() {
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

				flow.Inspect(
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
}
