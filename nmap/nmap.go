package nmap

//https://nmap.org/man/ru/man-port-scanning-techniques.html
import (
	"github.com/Ullaakut/nmap"
	"github.com/sirupsen/logrus"
	"strconv"
	"testtask/proto"
)

func Scanner(targets []string, tcpPorts []int32) ([]*proto.TargetResult, error) {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(targets...),
		nmap.WithPorts(arrInt32toArrStr(tcpPorts)...),
		nmap.WithScripts("vulners"), //Для каждого доступного CPE скрипт выводит известные vuln (ссылки на соответствующую информацию) и соответствующие оценки CVSS.
		nmap.WithServiceInfo(),
		nmap.WithVersionAll(),
		nmap.WithFilterPort(func(p nmap.Port) bool {
			// Filter out no open ports.
			return p.State.String() == "open"
		}),
		nmap.WithFilterHost(func(h nmap.Host) bool {
			// Filter out hosts with no open ports.
			for idx := range h.Ports {
				if h.Ports[idx].Status() == "open" {
					return true
				}
			}
			return false
		}),
	) //не сч закрытые порты
	if err != nil {
		logrus.WithFields(
			logrus.Fields{
				"package": "nmap",
				"func":    "Scanner",
				"method":  "NewScanner",
			}).Fatalf("unable to create nmap scanner: %v", err)

	}
	result, warnings, err := scanner.Run()
	if err != nil {
		logrus.WithFields(
			logrus.Fields{
				"package": "nmap",
				"func":    "Scanner",
				"method":  "Run",
			}).Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		logrus.WithFields(
			logrus.Fields{
				"package": "nmap",
				"func":    "Scanner",
				"method":  "Run",
			}).Warningf("Warnings: \n %v", warnings)
	}
	// Use the results to print an example output
	TarRes := make([]*proto.TargetResult, 0)
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		target := &proto.TargetResult{Target: host.Addresses[0].Addr}
		services := make([]*proto.Service, 0)
		for _, port := range host.Ports {
			var version string
			if len(port.Service.Product) != 0 {
				version = port.Service.Version
			}

			vulner := make([]*proto.Vulnerability, 0)
			for _, v := range port.Scripts {
				for _, t := range v.Tables {
					for _, tt := range t.Tables {
						//распарсить xml
						vulner = append(vulner, parsvulns(&tt))
					}
				}
			}
			logrus.Infof("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)

			services = append(services, &proto.Service{Name: port.Service.Name, TcpPort: int32(port.ID), Version: version, Vulns: vulner})
		}
		target.Services = services
		TarRes = append(TarRes, target)
	}
	logrus.Infof("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
	return TarRes, nil
}

func parsvulns(table *nmap.Table) *proto.Vulnerability {
	var id string
	var cvss float32
	for _, v := range table.Elements {
		switch v.Key {
		case "cvss":
			cvss64, err := strconv.ParseFloat(v.Value, 32)
			if err != nil {
				logrus.WithFields(
					logrus.Fields{
						"package": "nmap",
						"func":    "parsvulns",
						"method":  "ParseFloat",
					}).Error(err)
			} else {
				cvss = float32(cvss64)
			}
		case "id":
			id = v.Value
		}
	}
	return &proto.Vulnerability{Identifier: id, CvssScore: cvss}
}

func arrInt32toArrStr(arrInt []int32) []string {
	arrStr := make([]string, len(arrInt))
	for i := range arrInt {
		arrStr[i] = strconv.Itoa(int(arrInt[i]))
	}
	return arrStr
}
