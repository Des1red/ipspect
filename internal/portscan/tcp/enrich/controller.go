package enrich

import (
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"ipspect/internal/output"
	"ipspect/internal/portscan/tcp/enrich/fingerprint"
	"ipspect/internal/portscan/tcp/enrich/resolve"
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

	output.Log("debug", "tcp.enrich: loading IANA ports database")

	if err := load.LoadPorts(); err != nil {
		output.Log("debug", "tcp.enrich: database loading failed: "+err.Error())
		enrichTimer.Stop()
		return err
	}

	output.Log("debug", "tcp.enrich: IANA ports database loaded")

	for _, protocol := range []app.Protocol{
		app.TCPConnect,
		app.HTTP,
		app.HTTPS,
		app.DNSTCP,
	} {
		app.Start(protocol)
		defer app.Stop(protocol)
	}

	output.Log("debug", "tcp.enrich: starting port enrichment workers")

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

	output.Log("debug", "tcp.enrich: port enrichment completed")

	enrichTimer.Stop()

	// Stage 2: Protocol fingerprinting.
	fingerprintTimer := scantime.New(
		"Protocol Fingerprinting",
	)

	output.Log("debug", "tcp.fingerprint: starting protocol fingerprinting")

	if err := fingerprint.Controller(); err != nil {
		output.Log("debug", "tcp.fingerprint: failed: "+err.Error())
		fingerprintTimer.Stop()
		return err
	}

	output.Log("debug", "tcp.fingerprint: protocol fingerprinting completed")

	fingerprintTimer.Stop()

	// Stage 3: Service resolution.
	resolutionTimer := scantime.New(
		"Service Resolution",
	)

	output.Log("debug", "tcp.resolve: starting service resolution")

	resolve.Controller()

	output.Log("debug", "tcp.resolve: service resolution completed")

	resolutionTimer.Stop()

	return nil
}
