package resolve

import (
	"ipspect/internal/analyzer/result"
	"ipspect/internal/models"
)

func Controller() {
	for h := range models.LOOT.Hosts {
		host := &models.LOOT.Hosts[h]

		for i := range host.Details {
			detail := &host.Details[i]

			if detail.State != "open" {
				continue
			}

			result.ResolveService(detail)
		}
	}
}
