package cmd

import (
	"fmt"
	"ipspect/internal"
	"ipspect/internal/bootstrap"
	"ipspect/internal/models"
	"ipspect/internal/output"
	"ipspect/internal/portscan"
	"ipspect/internal/time"
	"os"
)

var (
	saveResults bool

	flagICMP bool
	flagARP  bool
	flagTCP  bool
)

func flagcheck() {
	internal.SetDefaultPorts()

	if len(os.Args) < 2 {
		return
	}

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		switch arg {
		case "-s":
			saveResults = true

		case "-p":
			if i+1 >= len(os.Args) {
				fmt.Println("-p requires a port or port range")
				fmt.Println("examples:")
				fmt.Println("  -p 22")
				fmt.Println("  -p 1-22")
				os.Exit(1)
			}

			i++

			if err := internal.SetPorts(os.Args[i]); err != nil {
				fmt.Println("invalid port range:", err)
				os.Exit(1)
			}

		case "-icmp":
			flagICMP = true

		case "-arp":
			flagARP = true

		case "-tcp":
			flagTCP = true

		case "install":
			bootstrap.Install()
			os.Exit(0)

		case "uninstall":
			bootstrap.Uninstall()
			os.Exit(0)

		case "help":
			help()
			os.Exit(0)

		case "version":
			version()
			os.Exit(0)

		default:
			fmt.Println("unknown argument:", arg)
			help()
			os.Exit(1)
		}
	}
}

func scan() {
	activateEngines()

	internal.Target()

	portscan.Run()

	time.PrintTimes()
}

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
