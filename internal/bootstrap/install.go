package bootstrap

import (
	"fmt"

	instll "github.com/Des1red/goinstall/cmd"
)

const binName = "ipspect"

func Install() {
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
		instll.Install(
			true,
			true,
		)

	if err != nil {
		fmt.Println(
			"installation failed:",
			err,
		)

		return
	}

	fmt.Println(
		"ipspect installed.",
	)
}