package ping

import (
	"ipspect/internal/models"
	"net"
	"sort"
)

func (s *scanState) storeResults() {
	result := make(
		[]net.IP,
		0,
		len(s.live),
	)

	for _, ip := range s.live {
		result = append(
			result,
			ip,
		)
	}

	sort.Slice(
		result,
		func(i, j int) bool {
			return lessIP(
				result[i],
				result[j],
			)
		},
	)

	models.LOOT.ICMPReachable = make(
		[]string,
		len(result),
	)

	for i, ip := range result {
		models.LOOT.ICMPReachable[i] =
			ip.String()
	}
}

func lessIP(a, b net.IP) bool {
	a4 := a.To4()
	b4 := b.To4()

	if a4 == nil || b4 == nil {
		return a.String() < b.String()
	}

	for i := 0; i < 4; i++ {
		if a4[i] != b4[i] {
			return a4[i] < b4[i]
		}
	}

	return false
}
