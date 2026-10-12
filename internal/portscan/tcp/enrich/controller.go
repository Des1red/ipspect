package enrich

import (
	"ipspect/internal/models"
	"ipspect/internal/portscan/tcp/enrich/fingerprint"
	scantime "ipspect/internal/time"
	"sync"
)

const enrichWorkers = 128

type enrichJob struct {
	hostIndex   int
	detailIndex int
}

func Controller() error {
	enrichTimer := scantime.New("TCP Enrichment")

	if err := loadServices(); err != nil {
		enrichTimer.Stop()
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

	enrichTimer.Stop()

	// Stage 2: Actual protocol fingerprinting.
	// HTTP headers are collected during these probes.
	fingerprintTimer := scantime.New("Protocol Fingerprinting")

	fingerprint.Controller()

	fingerprintTimer.Stop()

	// Stage 3: Final service resolution.
	resolutionTimer := scantime.New("Service Resolution")

	resolveServices()

	resolutionTimer.Stop()

	return nil
}
