package x509

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"github.com/vbhledger-blockchain/library/gm/sm/sm2"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func TestSm2(t *testing.T) {
	random := rand.Reader
	priv, err := sm2.GenerateKey(random) // 生成密钥对
	if err != nil {
		log.Fatal(err)
		return
	}
	pub := &priv.PublicKey
	msg := []byte("123456")
	d0, err := pub.Encrypt(msg)
	if err != nil {
		return
	}
	// fmt.Printf("Cipher text = %v\n", d0)
	d1, err := priv.Decrypt(d0)
	if err != nil {
		fmt.Printf("Error: failed to decrypt: %v\n", err)
	}
	fmt.Printf("clear text = %s\n", d1)
	fmt.Printf("priv text = %v\n", priv)

	ok, err := WritePrivateKeytoPem("priv.pem", priv, nil) // 生成密钥文件
	if ok != true {
		log.Fatal(err)
		return
	}
	pubKey, _ := priv.Public().(*sm2.PublicKey)
	ok, err = WritePublicKeytoPem("pub.pem", pubKey, nil) // 生成公钥文件
	if ok != true {
		log.Fatal(err)
		return
	}
	msg = []byte("test")
	err = ioutil.WriteFile("ifile", msg, os.FileMode(0644)) // 生成测试文件
	if err != nil {
		log.Fatal(err)
		return
	}
	privKey, err := ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Printf("sssssdfffffffff")
	pubKey, err = ReadPublicKeyFromPem("pub.pem", nil) // 读取公钥
	if err != nil {
		log.Fatal(err)
		return
	}
	msg, _ = ioutil.ReadFile("ifile") // 从文件读取数据
	var sm2Privkey *sm2.PrivateKey
	switch privKey.(type) {
	case *sm2.PrivateKey:
		sm2Privkey, ok = privKey.(*sm2.PrivateKey)
		if !ok {
			log.Fatal("断言类型不对")
			return
		}
		fmt.Println("sm2 ", sm2Privkey)
	}
	sign, err := sm2Privkey.Sign(rand.Reader, msg, nil) // 签名
	if err != nil {
		log.Fatal(err)
		return
	}
	err = ioutil.WriteFile("ofile", sign, os.FileMode(0644))
	if err != nil {
		log.Fatal(err)
		return
	}
	signdata, _ := ioutil.ReadFile("ofile")
	ok = sm2Privkey.Verify(msg, signdata) // 密钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	fmt.Printf("\n --------------------------------------------\n")
	ok = pubKey.Verify(msg, signdata) // 公钥验证
	if ok != true {
		fmt.Printf("Verify error\n")
	} else {
		fmt.Printf("Verify ok\n")
	}
	templateReq := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,
	}
	fmt.Printf("Verify aaaaaaa ok\n")
	_, err = CreateCertificateRequestToPem("req.pem", &templateReq, sm2Privkey)
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Printf("Verify bbbbbbb ok\n")
	req, err := ReadCertificateRequestFromPem("req.pem")
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Printf("Verify cccccc ok\n")
	err = req.CheckSignature()
	if err != nil {
		log.Fatalf("Request CheckSignature error:%v", err)
		return
	} else {
		fmt.Printf("CheckSignature ok\n")
	}

	fmt.Printf("Verify 第二遍 ok\n")
	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	pubKey, _ = priv.Public().(*sm2.PublicKey)
	ok, _ = CreateCertificateToPem("cert.pem", &template, &template, pubKey, sm2Privkey)
	if ok != true {
		fmt.Printf("failed to create cert file\n")
	}
	cert, err := ReadCertificateFromPem("cert.pem")
	if err != nil {
		fmt.Printf("failed to read cert file")
	}

	derBytes, err := CreateCertificate(random, &template, &template, pubKey, sm2Privkey)
	if err != nil {
		t.Errorf("%s: failed to create certificate: %s", pubKey, err)
	}

	//4.解析成证书格式的二进制文件
	certa, err := ParseCertificate(derBytes)
	if err != nil {
		t.Errorf("%v: failed to parse certificate: %v", certa, err)
	}
	err = cert.CheckSignatureFrom(certa)
	if err != nil {
		t.Errorf("%v: signature verification failed: %v", pubKey, err)
	}

	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		log.Fatal(err)
		return
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}

func TestSm2Verify(t *testing.T) {
	cert, err := ReadCertificateFromPem("cert.pem")
	if err != nil {
		fmt.Printf("failed to read cert file")
		log.Fatal(err)
	}

	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		log.Fatal(err)
		return
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}

func BenchmarkSM2(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := sm2.GenerateKey(rand.Reader) // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
		if err != nil {
			log.Fatal(err)
		}
		priv.Verify(msg, sign) // 密钥验证
		// if ok != true {
		// 	fmt.Printf("Verify error\n")
		// } else {
		// 	fmt.Printf("Verify ok\n")
		// }
	}
}
