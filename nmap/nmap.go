package nmap

import (
	"fmt"
	"github.com/Ullaakut/nmap"
	"log"
)

type TargetRes struct {
	Target  string
	Service services
}
type services struct {
	Name          string
	Version       string
	TcpPort       int32
	Vulnerability vulns
}
type vulns struct {
	Identifier string
	Cvss_score float64
}

func Scanner(targets []string, tcpPorts int32) {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targets...),
		nmap.WithPorts(fmt.Sprintf("%d", tcpPorts))) //todo сделать tcpPorts!  (80,443,843)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}
	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}
	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
