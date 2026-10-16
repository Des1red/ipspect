package enrich

import (
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"ipspect/internal/scanner/tcp/enrich/fingerprint"
	"ipspect/internal/scanner/tcp/enrich/resolve"
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

	for _, protocol := range []app.Protocol{
		app.TCPConnect,
		app.HTTP,
		app.HTTPS,
		app.DNSTCP,
	} {
		app.Start(protocol)
		defer app.Stop(protocol)
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

	fingerprintTimer := scantime.New(
		"Protocol Fingerprinting",
	)

	if err := fingerprint.Controller(); err != nil {
		fingerprintTimer.Stop()
		return err
	}

	fingerprintTimer.Stop()

	resolutionTimer := scantime.New(
		"Service Resolution",
	)

	resolve.Controller()

	resolutionTimer.Stop()

	return nil
}
