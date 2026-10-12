package app

import (
	"errors"
	"net"
)

func TimeoutOnError(
	protocol Protocol,
	err error,
) {
	var netErr net.Error

	if errors.As(err, &netErr) &&
		netErr.Timeout() {

		Timeout(protocol)
	}
}
