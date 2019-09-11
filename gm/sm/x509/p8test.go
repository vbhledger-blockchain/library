package x509

import (
	"encoding/pem"
	"github.com/vbhledger-blockchain/library/gm/sm/sm2"
	"os"
)

func WritePublicKeytoPem(FileName string, key *sm2.PublicKey, _ []byte) (bool, error) {
	der, err := MarshalSm2PublicKey(key)
	if err != nil {
		return false, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	file, err := os.Create(FileName)
	defer file.Close()
	if err != nil {
		return false, err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return false, err
	}
	return true, nil
}
