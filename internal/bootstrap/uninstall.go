package bootstrap

import (
	"fmt"

	instll "github.com/Des1red/goinstall/cmd"
)

func Uninstall() {
	err :=
		instll.SetBinaryName(
			binName,
		)

	if err != nil {
		fmt.Println(
			"failed to set binary name:",
			err,
		)

		return
	}

	err =
		instll.Uninstall(
			true,
			true,
		)

	if err != nil {
		fmt.Println(
			"uninstallation failed:",
			err,
		)

		return
	}

	fmt.Println(
		"ipspect removed.",
	)
}