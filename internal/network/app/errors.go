package app

import (
	"errors"
	"net"
)

func Fail(
	protocol Protocol,
	err error,
) {
	if err == nil {
		return
	}

	var netErr net.Error

	if errors.As(err, &netErr) &&
		netErr.Timeout() {
		Timeout(protocol)
		return
	}

	Drop(protocol)
}
