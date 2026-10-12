package cmd

import (
	"fmt"
	"os"
	"strings"

	"ipspect/internal"
	"ipspect/internal/bootstrap"
	"ipspect/internal/models"

	"github.com/Des1red/clihelp"
)

func help() {
	description := `IPSpect is a command-line IPv4 network scanner supporting
ICMP echo discovery, ARP device identification, and TCP SYN
port scanning with service fingerprinting and enrichment.`

	fmt.Println(description)
	fmt.Println()

	fmt.Println("Usage:")
	fmt.Println("  ipspect [command]")
	fmt.Println("  ipspect [flags]")
	fmt.Println()

	fmt.Println("Commands:")
	clihelp.Print(
		clihelp.F(
			"install",
			"",
			"build and install the binary",
		),
		clihelp.F(
			"uninstall",
			"",
			"remove the installed binary",
		),
		clihelp.F(
			"help, --help",
			"",
			"show this help message",
		),
		clihelp.F(
			"version, --version",
			"",
			"show version",
		),
	)

	fmt.Println()

	fmt.Println("Flags:")
	clihelp.Print(
		clihelp.F(
			"-s, --save",
			"",
			"save scan results as Markdown",
		),
		clihelp.F(
			"-p, --ports",
			"<ports>",
			"scan TCP ports, lists, and ranges",
		),
		clihelp.F(
			"-icmp, --icmp",
			"",
			"enable ICMP echo discovery",
		),
		clihelp.F(
			"-arp, --arp",
			"",
			"enable ARP discovery on local networks",
		),
		clihelp.F(
			"-tcp, --tcp",
			"",
			"enable TCP SYN scanning and service identification",
		),
		clihelp.F(
			"-v, --verbose",
			"",
			"enable verbose output",
		),
	)

	fmt.Println()

	fmt.Println("Engine Selection:")
	fmt.Println(
		"  By default, all three engines are enabled.",
	)
	fmt.Println(
		"  When engine flags are specified, only the selected",
	)
	fmt.Println(
		"  engines will execute.",
	)
	fmt.Println(
		"  Multiple engine flags can be combined in any order.",
	)
	fmt.Println(
		"  Port selection requires TCP to be enabled.",
	)
	fmt.Println()

	clihelp.Print(
		clihelp.F(
			"ipspect",
			"",
			"run ICMP, ARP, and TCP",
		),
		clihelp.F(
			"ipspect --icmp",
			"",
			"run only ICMP discovery",
		),
		clihelp.F(
			"ipspect --arp",
			"",
			"run only ARP discovery",
		),
		clihelp.F(
			"ipspect --tcp",
			"",
			"run only TCP scanning and enrichment",
		),
		clihelp.F(
			"ipspect --icmp --arp",
			"",
			"run ICMP and ARP discovery",
		),
		clihelp.F(
			"ipspect --arp --tcp",
			"",
			"run ARP discovery and TCP scanning",
		),
		clihelp.F(
			"ipspect --tcp --ports 80,443",
			"",
			"run TCP scanning on selected ports",
		),
		clihelp.F(
			"ipspect -p 22",
			"",
			"run all default engines, scanning TCP port 22",
		),
	)

	fmt.Println()

	fmt.Println("Targets:")
	clihelp.Print(
		clihelp.F(
			"IP",
			"192.168.1.10",
			"scan a single IPv4 address",
		),
		clihelp.F(
			"CIDR",
			"192.168.1.0/24",
			"scan an IPv4 subnet",
		),
		clihelp.F(
			"*Target selection",
			"",
			"on runtime",
		),
	)

	fmt.Println()

	fmt.Println("Defaults:")
	clihelp.Print(
		clihelp.F(
			"engines",
			"ICMP, ARP, TCP",
			"all enabled unless engine flags are specified",
		),
		clihelp.F(
			"ports",
			"1-65535",
			"used when -p is not specified",
		),
		clihelp.F(
			"execution",
			"ICMP -> ARP -> TCP",
			"selected engines run in this order",
		),
	)

	fmt.Println()
}

func version() {
	fmt.Println(models.Version)
}

var (
	saveResults bool
	verbose     bool

	flagICMP bool
	flagARP  bool
	flagTCP  bool
)

func flagError(
	message string,
) {
	fmt.Fprintln(
		os.Stderr,
		"ipspect:", message,
	)

	os.Exit(1)
}

func validateFlags(
	portsSpecified bool,
) error {
	engineSelected :=
		flagICMP ||
			flagARP ||
			flagTCP

	// When no engine is explicitly selected,
	// all three engines run by default.
	tcpEnabled :=
		!engineSelected ||
			flagTCP

	if portsSpecified && !tcpEnabled {
		return fmt.Errorf(
			"-p/--ports requires TCP scanning; " +
				"enable -tcp/--tcp or omit engine flags",
		)
	}

	return nil
}

func flagcheck() {
	internal.SetDefaultPorts()

	if len(os.Args) < 2 {
		return
	}

	portsSpecified := false

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]

		switch arg {
		case "-s", "--s", "--save":
			saveResults = true

		case "-v", "--v", "--verbose":
			verbose = true

		case "-p", "--p", "--ports":
			if portsSpecified {
				flagError(
					"port selection may only be specified once",
				)
			}

			if i+1 >= len(os.Args) ||
				strings.HasPrefix(
					os.Args[i+1],
					"-",
				) {

				flagError(
					"-p/--ports requires a port specification " +
						"(examples: 23, 1-1000, 22,80,443)",
				)
			}

			i++

			if err := internal.SetPorts(
				os.Args[i],
			); err != nil {
				flagError(
					fmt.Sprintf(
						"invalid port specification: %v",
						err,
					),
				)
			}

			portsSpecified = true

		case "-icmp", "--icmp":
			flagICMP = true

		case "-arp", "--arp":
			flagARP = true

		case "-tcp", "--tcp":
			flagTCP = true

		case "install", "--install":
			if len(os.Args) != 2 {
				flagError(
					"install cannot be combined with other arguments",
				)
			}

			bootstrap.Install()
			os.Exit(0)

		case "uninstall", "--uninstall":
			if len(os.Args) != 2 {
				flagError(
					"uninstall cannot be combined with other arguments",
				)
			}

			bootstrap.Uninstall()
			os.Exit(0)

		case "help", "-h", "--help":
			if len(os.Args) != 2 {
				flagError(
					"help cannot be combined with other arguments",
				)
			}

			help()
			os.Exit(0)

		case "version", "--version":
			if len(os.Args) != 2 {
				flagError(
					"version cannot be combined with other arguments",
				)
			}

			version()
			os.Exit(0)

		default:
			flagError(
				"unknown argument: " + arg,
			)
		}
	}

	if err := validateFlags(
		portsSpecified,
	); err != nil {
		flagError(err.Error())
	}
}
