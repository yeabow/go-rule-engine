package ruler

import (
	"bytes"
	"net"
	"regexp"
	"strconv"
	"strings"
)

func CheckIP(ip string, list string) bool {
	list = strings.TrimSpace(list)

	if list == "" {
		return false
	}

	ips := strings.Split(list, ",")
	if len(ips) != 0 {
		allow := false
		regex := "(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
		for _, allowIP := range ips {

			allowIP = strings.TrimSpace(allowIP)

			if allowIP == "0.0.0.0" {
				allow = true
				break
			}

			//ip, 192.168.1.234
			matched, err := regexp.MatchString("^"+regex+"$", allowIP)
			if err == nil && matched {
				if ip == allowIP {
					allow = true
					break
				}
			}

			//192.168.0.1/16
			matched, err = regexp.MatchString("^"+regex+"\\/([1-9]|[1-2]\\d|3[0-2])$", allowIP)
			if err == nil && matched {
				if isBelong(ip, allowIP) {
					allow = true
					break
				}
			}

			//192.168.1.2-192.168.2.8,192.168.1.2-16
			if strings.Index(allowIP, "-") != -1 {
				allows := strings.Split(allowIP, "-")
				if len(allows) == 2 {
					var begin string
					var end string
					matched, err := regexp.MatchString("^"+regex+"$", allows[0])
					if err == nil && matched {
						begin = allows[0]
					} else {
						continue
					}

					matched, err = regexp.MatchString("^"+regex+"$", allows[1])
					if err == nil && matched {
						end = allows[1]
					} else {
						if isNum(allows[1]) {
							splits := strings.Split(begin, ".")
							if len(splits) == 4 {
								end = splits[0] + "." + splits[1] + "." + splits[2] + "." + allows[1]
							}
						}
					}

					if check(ip, begin, end) {
						allow = true
						break
					}
				}
			}
		}

		if !allow {
			return false
		}
	}
	return true
}

func isNum(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

func check(ip string, begin, end string) bool {
	b := net.ParseIP(begin)
	e := net.ParseIP(end)
	trial := net.ParseIP(ip)
	if trial.To4() == nil {
		return false
	}
	if bytes.Compare(trial, b) >= 0 && bytes.Compare(trial, e) <= 0 {
		return true
	}
	return false
}

func isBelong(ip, cidr string) bool {
	_, ipNet, _ := net.ParseCIDR(cidr)
	checkIP := net.ParseIP(ip)
	if ipNet.Contains(checkIP) {
		return true
	} else {
		return false
	}
}
