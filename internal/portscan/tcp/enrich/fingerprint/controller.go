package fingerprint

import (
	"ipspect/internal/models"
	"strings"
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
	passive := detectBanner(detail)

	if passive.Service != "" &&
		passive.Service != "http" {

		recordMatches(
			detail,
			[]models.FingerprintMatch{passive},
		)

		return
	}

	// IANA only determines probe order.
	// It does not confirm the actual service.
	if detail.DBLookup == "domain" {
		dns := probeDNS(
			ip,
			detail.Port,
		)

		if dns.Service != "" {
			recordMatches(
				detail,
				[]models.FingerprintMatch{dns},
			)

			return
		}
	}

	matches := make(
		[]models.FingerprintMatch,
		0,
		2,
	)

	// Always check plaintext HTTP independently.
	http := probeHTTP(
		ip,
		detail.Port,
		false,
	)

	if http.Service != "" {
		matches = append(matches, http)
	}

	// Always check HTTPS independently.
	// HTTP success does not prevent this probe.
	https := probeHTTP(
		ip,
		detail.Port,
		true,
	)

	if https.Service != "" {
		matches = append(matches, https)
	}

	if len(matches) > 0 {
		recordMatches(detail, matches)
		return
	}

	// DNS may also run on nonstandard ports.
	if detail.DBLookup != "domain" {
		dns := probeDNS(
			ip,
			detail.Port,
		)

		if dns.Service != "" {
			recordMatches(
				detail,
				[]models.FingerprintMatch{dns},
			)

			return
		}
	}

	if passive.Service != "" {
		recordMatches(
			detail,
			[]models.FingerprintMatch{passive},
		)

		return
	}

	detail.Fingerprint = models.FingerprintResult{
		Evidence: "No matching protocol signature",
	}
}

func recordMatches(
	detail *models.PortDetail,
	matches []models.FingerprintMatch,
) {
	fp := models.FingerprintResult{
		Matches:    matches,
		Confidence: "high",
	}

	names := make([]string, 0, len(matches))
	products := make([]string, 0, len(matches))
	evidences := make([]string, 0, len(matches))

	for _, match := range matches {
		names = append(
			names,
			match.Service,
		)

		evidences = append(
			evidences,
			match.Evidence,
		)

		if match.Product != "" {
			products = append(
				products,
				match.Product,
			)
		}

		if detail.Banner == "" &&
			match.Banner != "" {

			detail.Banner = match.Banner
		}

		if len(detail.Headers) == 0 &&
			len(match.Headers) > 0 {

			detail.Headers = match.Headers
		}
	}

	fp.Service = strings.Join(names, "+")
	fp.Product = strings.Join(products, " | ")
	fp.Evidence = strings.Join(evidences, "; ")

	detail.Fingerprint = fp
}
