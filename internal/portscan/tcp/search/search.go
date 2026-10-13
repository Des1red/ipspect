package search

import (
	"errors"
	"fmt"
	"syscall"
	"time"
)

func (s *scanState) run() error {
	sendTicker := time.NewTicker(
		time.Second / synPacketsPerSecond,
	)

	defer sendTicker.Stop()

	expireTicker := time.NewTicker(
		10 * time.Millisecond,
	)

	defer expireTicker.Stop()

	for s.moreJobs || len(s.pending) > 0 {
		select {
		case reply := <-s.scanner.Replies():
			s.handleReply(reply)

		case <-expireTicker.C:
			s.expireProbes(
				time.Now(),
			)

		case <-sendTicker.C:
			now := time.Now()

			if now.Before(s.pauseUntil) {
				continue
			}

			retried, err := s.retryDue(now)
			if err != nil {
				return err
			}

			if retried {
				continue
			}

			if err := s.dispatch(); err != nil {
				return err
			}

		case err := <-s.scanner.Errors():
			if err != nil {
				return fmt.Errorf(
					"SYN receive error: %w",
					err,
				)
			}
		}
	}

	return nil
}

func (s *scanState) recoverableSendError(
	err error,
) bool {
	if !errors.Is(err, syscall.ENOBUFS) &&
		!errors.Is(err, syscall.EAGAIN) {
		return false
	}

	s.consecutiveSendFailures++

	if s.consecutiveSendFailures >=
		synMaxSendFailures {
		return false
	}

	s.pauseUntil = time.Now().Add(
		synCongestionPause,
	)

	return true
}
