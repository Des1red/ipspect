package fingerprint

import (
	"ipspect/internal/models"
	"sync"
)

const fingerprintWorkers = 32

type fingerprintJob struct {
	hostIndex   int
	detailIndex int
}

func Controller() {
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
}

func inspect(
	ip string,
	detail *models.PortDetail,
) {
	result := detectBanner(detail)

	if result.Service != "" {
		detail.Fingerprint = result
		return
	}

	result, banner := probeHTTP(
		ip,
		detail.Port,
		false,
	)

	if result.Service != "" {
		detail.Fingerprint = result

		if detail.Banner == "" {
			detail.Banner = banner
		}

		return
	}

	result, banner = probeHTTP(
		ip,
		detail.Port,
		true,
	)

	if result.Service != "" {
		detail.Fingerprint = result

		if detail.Banner == "" {
			detail.Banner = banner
		}

		return
	}

	detail.Fingerprint = models.FingerprintResult{
		Evidence: "No matching protocol signature",
	}
}
