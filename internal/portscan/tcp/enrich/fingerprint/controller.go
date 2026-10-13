package fingerprint

import (
	"ipspect/internal/database/load"
	"ipspect/internal/database/load/requests"
	"ipspect/internal/models"
	"sync"
)

const fingerprintWorkers = 32

type fingerprintJob struct {
	hostIndex   int
	detailIndex int
}

func Controller() error {
	if err := load.LoadRecog(); err != nil {
		return err
	}

	if err := requests.Load(); err != nil {
		return err
	}

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

	return nil
}
