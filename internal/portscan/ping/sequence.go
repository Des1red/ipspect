package ping

func reserveICMPSequence(
	next *int,
	used map[int]struct{},
) (int, bool) {
	for attempts := 0; attempts < 65535; attempts++ {
		if *next < 1 ||
			*next > 65535 {

			*next = 1
		}

		seq := *next

		*next = *next + 1

		if _, exists := used[seq]; exists {
			continue
		}

		used[seq] = struct{}{}

		return seq, true
	}

	return 0, false
}
