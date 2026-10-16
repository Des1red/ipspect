package fingerprint

import (
	"ipspect/internal/models"
	"ipspect/internal/scanner/tcp/enrich/fingerprint/flow"
	"sync"
)

const fingerprintWorkers = 32

type fingerprintJob struct {
	hostIndex   int
	detailIndex int
}

func runFingerprintWorkers() {
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
		}
	}

	close(jobs)
	wg.Wait()
}
