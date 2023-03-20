package nmap

//https://nmap.org/man/ru/man-port-scanning-techniques.html
import (
	"fmt"
	"github.com/Ullaakut/nmap"
	"log"
	"strconv"
	"testtask/proto"
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

func Scanner(targets []string, tcpPorts []int32) ([]*proto.TargetResult, error) {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targets...),
		nmap.WithPorts(arrInt32toArrStr(tcpPorts)...),
		nmap.WithScripts("vulners"), //Для каждого доступного CPE скрипт выводит известные vuln (ссылки на соответствующую информацию) и соответствующие оценки CVSS.
		nmap.WithServiceInfo(),
		nmap.WithVersionAll(),
	) //не сч закрытые порты
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
	TarRes := make([]*proto.TargetResult, 0)
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])
		target := &proto.TargetResult{Target: host.Addresses[0].Addr}
		services := make([]*proto.Service, 0)
		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
			services = append(services, &proto.Service{Name: port.Service.Name, TcpPort: int32(port.ID)})
		}
		target.Services = services
		TarRes = append(TarRes, target)
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
	return TarRes, nil
}

func arrInt32toArrStr(arr []int32) []string {
	arrInt := make([]int32, len(arr))
	copy(arrInt, arr)
	arrStr := make([]string, len(arrInt))
	for i := range arrInt {
		arrStr[i] = strconv.Itoa(int(arrInt[i]))
	}
	return arrStr
}
