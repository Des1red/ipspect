package enrich

import (
	"ipspect/internal/models"
	"sync"
)

const enrichWorkers = 128

type enrichJob struct {
	hostIndex   int
	detailIndex int
}

func Controller() {
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
}
