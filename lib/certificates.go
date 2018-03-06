package lib

import (
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"
	"time"
	"bufio"
	"github.com/adamwalach/openvpn-web-ui/models"
	"github.com/astaxie/beego"
	"log"
)

//Cert
//https://groups.google.com/d/msg/mailing.openssl.users/gMRbePiuwV0/wTASgPhuPzkJ
type Cert struct {
	EntryType   string
	Expiration  string
	ExpirationT time.Time
	Revocation  string
	RevocationT time.Time
	Serial      string
	FileName    string
	Details     *Details
}

type Details struct {
	Name         string
	CN           string
	Country      string
	Organisation string
	Email        string
}

func ReadCerts(path string) ([]*Cert, error) {
	certs := make([]*Cert, 0, 0)
	text, err := ioutil.ReadFile(path)
	if err != nil {
		return certs, err
	}
	lines := strings.Split(trim(string(text)), "\n")
	for _, line := range lines {
		fields := strings.Split(trim(line), "\t")
		if len(fields) != 6 {
			return certs,
				fmt.Errorf("Incorrect number of lines in line: \n%s\n. Expected %d, found %d",
					line, 6, len(fields))
		}
		expT, _ := time.Parse("060102150405Z", fields[1])
		revT, _ := time.Parse("060102150405Z", fields[2])
		c := &Cert{
			EntryType:   fields[0],
			Expiration:  fields[1],
			ExpirationT: expT,
			Revocation:  fields[2],
			RevocationT: revT,
			Serial:      fields[3],
			FileName:    fields[4],
			Details:     parseDetails(fields[5]),
		}
		certs = append(certs, c)
	}

	return certs, nil
}

func parseDetails(d string) *Details {
	details := &Details{}
	lines := strings.Split(trim(string(d)), "/")
	for _, line := range lines {
		if strings.Contains(line, "") {
			fields := strings.Split(trim(line), "=")
			switch fields[0] {
			case "name":
				details.Name = fields[1]
			case "CN":
				details.CN = fields[1]
			case "C":
				details.Country = fields[1]
			case "O":
				details.Organisation = fields[1]
			case "emailAddress":
				details.Email = fields[1]
			default:
				beego.Warn(fmt.Sprintf("Undefined entry: %s", line))
			}
		}
	}
	return details
}

func trim(s string) string {
	return strings.Trim(strings.Trim(s, "\r\n"), "\n")
}

func CreateCertificate(name string, passphrase string) error {
	rsaPath := "/usr/share/easy-rsa/"
	varsPath := models.GlobalCfg.OVConfigPath + "keys/vars"
	cmd := exec.Command("/bin/bash", "-c",
		fmt.Sprintf(
			"source %s &&"+
				"export KEY_NAME=%s &&"+
				"%s/build-key --batch --pass %s", varsPath, name, rsaPath, name))
	cmd.Dir = models.GlobalCfg.OVConfigPath
	stdin, err := cmd.StdinPipe()
	if nil != err {
		beego.Debug("Error getting stdin pipe")
		beego.Error(err)
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		beego.Debug("Error getting stderr pipe")
		beego.Error(err)
		return err
	}
	errScanner := bufio.NewScanner(stderr)

	go func() {
		for errScanner.Scan() {
			log.Printf("Reading from subprocess: %s", errScanner.Text())
			stdin.Write([]byte(passphrase + "\n"))
		}
	} ()

	if err := cmd.Start(); nil != err {
		beego.Debug("Error running command")
		beego.Error(err)
		return err
	}
 
        err = cmd.Wait()
        if err != nil {
		beego.Debug("Error waiting for command")
		beego.Error(err)
                return err
        }

	return nil

}
