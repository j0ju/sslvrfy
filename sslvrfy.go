package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

func PrintCert(cert *x509.Certificate) {
	fmt.Println("  notBefore:", cert.NotBefore)
	fmt.Println("  notAfter :", cert.NotAfter)

	for i := range cert.IssuingCertificateURL {
		fmt.Printf("  IssuingCertificateURL: %s\n", cert.IssuingCertificateURL[i])
	}
	for i := range cert.OCSPServer {
		fmt.Printf("  OCSPServer: %s\n", cert.OCSPServer[i])
	}
	for i := range cert.DNSNames {
		fmt.Printf("  DNSNames: %s\n", cert.DNSNames[i])
	}
	for i := range cert.EmailAddresses {
		fmt.Printf("  EmailAddresses: %s\n", cert.EmailAddresses[i])
	}
	for i := range cert.IPAddresses {
		fmt.Printf("  IPAddresses: %s\n", cert.IPAddresses[i])
	}
}

func PrintPkixName(name pkix.Name) {
	for i := range name.Country {
		fmt.Printf("    C=%s\n", name.Country[i])
	}
	for i := range name.Organization {
		fmt.Printf("    O=%s\n", name.Organization[i])
	}
	for i := range name.OrganizationalUnit {
		fmt.Printf("    OU=%s\n", name.OrganizationalUnit[i])
	}
	for i := range name.Locality {
		fmt.Printf("    L=%s\n", name.Locality[i])
	}
	for i := range name.Province {
		fmt.Printf("    P=%s\n", name.Province[i])
	}
	for i := range name.StreetAddress {
		fmt.Printf("    A=%s\n", name.StreetAddress[i])
	}
	for i := range name.PostalCode {
		fmt.Printf("    PC=%s\n", name.PostalCode[i])
	}
	fmt.Printf("  CN=%s\n", name.CommonName)
	if name.SerialNumber != "" {
		fmt.Printf("  SN=%s\n", name.SerialNumber)
	}
}

func main() {

	isRootKnownCert := -1
	isChainValidated := -1
	isValidated := -1
	isSelfsigned := 0
	isChainInOrder := 0
	notAfterInDays := -1

	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	certPool := x509.NewCertPool()

	if len(os.Args) == 3 {
		dialer := net.Dialer{
			Timeout: time.Duration(5 * time.Second),
		}

		conf.ServerName = os.Args[1] // advertise SNI support and use server name
		conn, err := tls.DialWithDialer(&dialer, "tcp", os.Args[1]+":"+os.Args[2], conf)
		if err != nil {
			log.Println(err)
			return
		}
		defer conn.Close()

		// iterate on all certs presented by the SSL Server, in reverse order
		// the last Cert presented should be the root CA
		cstate := conn.ConnectionState()
		for i := len(cstate.PeerCertificates) - 1; i >= 0; i-- {
			fmt.Printf("\nCertificate %d\n", i)

			cert := cstate.PeerCertificates[i]
			PrintCert(cert)
			fmt.Printf("  Issuer:\n")
			PrintPkixName(cert.Issuer)
			fmt.Printf("  Subject:\n")
			PrintPkixName(cert.Subject)

			certPool.AddCert(cert)

			vrfyOpts := x509.VerifyOptions{
				Roots:   nil,
				DNSName: "",
			}

			// Test: past and future
			//time, e := time.Parse(time.RFC822Z, "02 Jan 08 15:04 -0700")
			//vrfyOpts.CurrentTime = time
			//fmt.Println(vrfyOpts.CurrentTime)

			// all but the first certificate is checked against its parent
			// all but the first certificate is checked against beeing selfsigned as ROOT CAs are mostly selfsigned
			if i != len(cstate.PeerCertificates)-1 {
				if e := cert.CheckSignatureFrom(cstate.PeerCertificates[i+1]); e != nil {
					fmt.Printf("  Signed by Parent: --- FAILED ---\n")
					isChainValidated = 0
				} else {
					fmt.Printf("  Signed by Parent: OK\n")
				}
				if e := cert.CheckSignatureFrom(cert); e == nil {
					fmt.Printf("  Signed by Self: --- SELF SIGNED ---\n")
					isSelfsigned = 1
				}
			}

			// first certificate is checked against systems CA certs
			// the others certs are checked only against previous certs
			if i != len(cstate.PeerCertificates)-1 {
				vrfyOpts.Roots = certPool
			}

			// check DNS name for last cert
			if i == 0 {
				vrfyOpts.DNSName = os.Args[1]
			}

			certChains, e := cert.Verify(vrfyOpts)
			if e != nil {
				if i != len(cstate.PeerCertificates)-1 {
					isRootKnownCert = 0
				}
				isChainValidated = 0
				fmt.Printf("  Verify: --- FAILED ---\n")
			} else {
				if i != len(cstate.PeerCertificates)-1 {
					if isRootKnownCert == -1 {
						isRootKnownCert = 1
					}
				}
				if isChainValidated == -1 {
					isChainValidated = 1
				}
				fmt.Printf("  Verify: OK\n")
			}

			if i == 0 {
				// check that the presented certificates are in correct chained order
				// iterate over all validated chains, with the same length as the server presented chain
				isChainInOrder = 0
				for i := range certChains {
					chain := certChains[i]
					isChainInOrder = 1
					if len(chain) == len(cstate.PeerCertificates) {
						for i := range cstate.PeerCertificates {
							if !cstate.PeerCertificates[i].Equal(chain[i]) {
								fmt.Printf("Certificate chain fail: %d\n", i)
								isChainInOrder = 0
								break
							}
						}
					}
				}
				isChainValidated = isChainValidated * isChainInOrder
				notAfterInDays = int(cert.NotAfter.Sub(time.Now()).Hours()) / 24
			}
			pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
			isValidated = isRootKnownCert * isChainValidated
		}

		fmt.Printf("isRootKnownCert:  %d\n", isRootKnownCert)
		fmt.Printf("isChainValidated: %d\n", isChainValidated)
		fmt.Printf("isValidated:      %d\n", isValidated)
		fmt.Printf("isSelfsigned:     %d\n", isSelfsigned)
		fmt.Printf("isChainInOrder:   %d\n", isChainInOrder)
		fmt.Printf("notAfterInDays:   %d days\n", notAfterInDays)
	} else {
		fmt.Printf("usage: sslvrfy <HOSTNAME> <PORT>\n")
	}

}
