package cmd

import (
	"fmt"
	"ipspect/internal"
	"ipspect/internal/models"
	"ipspect/internal/network/app"
	"ipspect/internal/output"
	"ipspect/internal/portscan"
	"ipspect/internal/time"
)

func activateEngines() {
	// No engine flags specified:
	// enable all engines by default.
	if !flagICMP &&
		!flagARP &&
		!flagTCP {

		models.ActiveEngines.ICMP = true
		models.ActiveEngines.ARP = true
		models.ActiveEngines.TCP = true

		return
	}

	// Enable only explicitly requested engines.
	models.ActiveEngines.ICMP = flagICMP
	models.ActiveEngines.ARP = flagARP
	models.ActiveEngines.TCP = flagTCP
}

func scan() {
	activateEngines()

	internal.Target()

	portscan.Run()

	statistics()
}

func statistics() {
	time.PrintTimes()
	app.Print()
}

func save() {
	filename, err := output.Save()

	if err != nil {
		fmt.Println(
			"failed to save results:",
			err,
		)
		return
	}

	fmt.Println(
		"results saved to",
		filename,
	)
}
