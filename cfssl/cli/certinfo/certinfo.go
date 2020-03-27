// Package certinfo implements the certinfo command
package certinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vbhledger-blockchain/library/gm/sm/x509"

	"github.com/jmoiron/sqlx"
	"github.com/vbhledger-blockchain/library/cfssl/certdb/dbconf"
	"github.com/vbhledger-blockchain/library/cfssl/certdb/sql"
	"github.com/vbhledger-blockchain/library/cfssl/certinfo"
	"github.com/vbhledger-blockchain/library/cfssl/cli"
)

// Usage text of 'cfssl certinfo'
var dataUsageText = `cfssl certinfo -- output certinfo about the given cert

Usage of certinfo:
	- Data from local certificate files
        cfssl certinfo -cert file
	- Data from local CSR file
        cfssl certinfo -csr file
	- Data from certificate from remote server.
        cfssl certinfo -domain domain_name
	- Data from CA storage
        cfssl certinfo -sn serial (requires -db-config and -aki)

Flags:
`

// flags used by 'cfssl certinfo'
var certinfoFlags = []string{"aki", "cert", "csr", "db-config", "domain", "serial"}

// certinfoMain is the main CLI of certinfo functionality
func certinfoMain(args []string, c cli.Config) (err error) {
	var cert *certinfo.Certificate
	var csr *x509.CertificateRequest

	if c.CertFile != "" {
		if c.CertFile == "-" {
			var certPEM []byte
			if certPEM, err = cli.ReadStdin(c.CertFile); err != nil {
				return
			}

			if cert, err = certinfo.ParseCertificatePEM(certPEM); err != nil {
				return
			}
		} else {
			if cert, err = certinfo.ParseCertificateFile(c.CertFile); err != nil {
				return
			}
		}
	} else if c.CSRFile != "" {
		if c.CSRFile == "-" {
			var csrPEM []byte
			if csrPEM, err = cli.ReadStdin(c.CSRFile); err != nil {
				return
			}
			if csr, err = certinfo.ParseCSRPEM(csrPEM); err != nil {
				return
			}
		} else {
			if csr, err = certinfo.ParseCSRFile(c.CSRFile); err != nil {
				return
			}
		}
	} else if c.Domain != "" {
		if cert, err = certinfo.ParseCertificateDomain(c.Domain); err != nil {
			return
		}
	} else if c.Serial != "" && c.AKI != "" {
		if c.DBConfigFile == "" {
			return errors.New("need DB config file (provide with -db-config)")
		}

		var db *sqlx.DB

		db, err = dbconf.DBFromConfig(c.DBConfigFile)
		if err != nil {
			return
		}

		dbAccessor := sql.NewAccessor(db)

		if cert, err = certinfo.ParseSerialNumber(c.Serial, c.AKI, dbAccessor); err != nil {
			return
		}
	} else {
		return errors.New("Must specify certinfo target through -cert, -csr, -domain or -serial + -aki")
	}

	var b []byte
	if cert != nil {
		b, err = json.MarshalIndent(cert, "", "  ")
	} else if csr != nil {
		b, err = json.MarshalIndent(csr, "", "  ")
	}

	if err != nil {
		return
	}

	fmt.Println(string(b))
	return
}

// Command assembles the definition of Command 'certinfo'
var Command = &cli.Command{UsageText: dataUsageText, Flags: certinfoFlags, Main: certinfoMain}
