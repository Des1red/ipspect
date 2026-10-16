package icmp

import (
	"errors"
	"fmt"
	"syscall"
	"time"
)

func (s *scanState) run() error {
	sendTicker := time.NewTicker(
		time.Second / icmpPacketsPerSecond,
	)

	defer sendTicker.Stop()

	expireTicker := time.NewTicker(
		25 * time.Millisecond,
	)

	defer expireTicker.Stop()

	for s.nextTarget < s.total ||
		len(s.pending) > 0 {

		select {
		case reply := <-s.scanner.replies:
			s.handleReply(reply)

		case <-expireTicker.C:
			s.expireProbes(time.Now())

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
		icmpMaxSendFailures {

		return false
	}

	s.pauseUntil = time.Now().Add(
		icmpCongestionPause,
	)

	return true
}

func (s *scanState) validateTransmission() error {
	if s.nextTarget > s.total {
		return fmt.Errorf(
			"ICMP target cursor exceeded target count",
		)
	}

	return nil
}
