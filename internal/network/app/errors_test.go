package app

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestFailureAccounting(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		timeouts int
		dropped  int
	}{
		{
			name: "timeout",
			err: fmt.Errorf(
				"read failed: %w",
				context.DeadlineExceeded,
			),
			timeouts: 1,
		},
		{
			name:    "connection error",
			err:     errors.New("connection refused"),
			dropped: 1,
		},
		{
			name: "no error",
			err:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Reset()
			defer Reset()

			Send(TCPConnect)

			Fail(TCPConnect, tt.err)

			stats := Snapshot().TCPConnect

			if stats.TimedOut != tt.timeouts {
				t.Fatalf(
					"expected %d timeouts, got %d",
					tt.timeouts,
					stats.TimedOut,
				)
			}

			if stats.Dropped != tt.dropped {
				t.Fatalf(
					"expected %d dropped, got %d",
					tt.dropped,
					stats.Dropped,
				)
			}

			if tt.err != nil {
				result := calculateDiagnostics(stats)

				if !result.valid ||
					result.coverage != 100 ||
					result.status != "Complete" {

					t.Fatalf(
						"unexpected diagnostics: %+v",
						result,
					)
				}
			}
		})
	}
}
