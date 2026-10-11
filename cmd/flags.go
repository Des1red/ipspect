package cmd

import (
	"fmt"

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
			"help",
			"",
			"show this help message",
		),
		clihelp.F(
			"version",
			"",
			"show version",
		),
	)

	fmt.Println()

	fmt.Println("Flags:")
	clihelp.Print(
		clihelp.F(
			"-s",
			"",
			"save scan results as Markdown",
		),
		clihelp.F(
			"-p",
			"<port>",
			"scan a single TCP port",
		),
		clihelp.F(
			"-p",
			"<ports>",
			"scan TCP ports, lists, and ranges",
		),
		clihelp.F(
			"-icmp",
			"",
			"enable ICMP echo discovery",
		),
		clihelp.F(
			"-arp",
			"",
			"enable ARP discovery on local networks",
		),
		clihelp.F(
			"-tcp",
			"",
			"enable TCP SYN scanning and service identification",
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
	fmt.Println()

	clihelp.Print(
		clihelp.F(
			"ipspect",
			"",
			"run ICMP, ARP, and TCP",
		),
		clihelp.F(
			"ipspect -icmp",
			"",
			"run only ICMP discovery",
		),
		clihelp.F(
			"ipspect -arp",
			"",
			"run only ARP discovery",
		),
		clihelp.F(
			"ipspect -tcp",
			"",
			"run only TCP scanning and enrichment",
		),
		clihelp.F(
			"ipspect -icmp -arp",
			"",
			"run ICMP and ARP discovery",
		),
		clihelp.F(
			"ipspect -arp -tcp",
			"",
			"run ARP discovery and TCP scanning",
		),
		clihelp.F(
			"ipspect -tcp -p 80,443",
			"",
			"run TCP scanning on selected ports",
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
