package enrich

import (
	"ipspect/internal/database/load"
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"sync"
)

const enrichWorkers = 32

func Controller(hosts []models.ARPResult) error {
	if len(hosts) == 0 {
		return nil
	}

	vendorErr := load.LoadIEEE()

	app.Start(app.DNS)
	app.Start(app.NetBIOS)

	defer app.Stop(app.DNS)
	defer app.Stop(app.NetBIOS)

	jobs := make(chan int)

	var wg sync.WaitGroup

	workers := enrichWorkers
	if len(hosts) < workers {
		workers = len(hosts)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for index := range jobs {
				host := &hosts[index]

				if vendorErr == nil {
					host.Vendor = load.LookupVendor(
						host.MAC,
					)
				}

				host.PTRName = lookupPTR(
					host.IP,
				)

				host.NetBIOSName = lookupNetBIOS(
					host.IP,
				)

				host.Hostname = host.PTRName

				if host.Hostname == "" {
					host.Hostname = host.NetBIOSName
				}
			}
		}()
	}

	for i := range hosts {
		jobs <- i
	}

	close(jobs)
	wg.Wait()

	return vendorErr
}
