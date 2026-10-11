package enrich

import (
	"ipspect/internal/models"
	"ipspect/internal/portscan/enrich/fingerprint"
	"sync"
)

const enrichWorkers = 128

type enrichJob struct {
	hostIndex   int
	detailIndex int
}

func Controller() error {
	if err := loadServices(); err != nil {
		return err
	}

	jobs := make(
		chan enrichJob,
		enrichWorkers,
	)

	var wg sync.WaitGroup

	for i := 0; i < enrichWorkers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for job := range jobs {
				enrichPort(
					job.hostIndex,
					job.detailIndex,
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

			jobs <- enrichJob{
				hostIndex:   h,
				detailIndex: i,
			}
		}
	}

	close(jobs)
	wg.Wait()

	// Stage 2: Actual protocol fingerprinting.
	// HTTP headers are collected during these probes.
	fingerprint.Controller()

	// Stage 3: Final service resolution.
	resolveServices()

	return nil
}
