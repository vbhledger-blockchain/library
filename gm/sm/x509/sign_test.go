package x509

import (
	"crypto/rand"
	"github.com/vbhledger-blockchain/library/gm/sm/sm2"
	"log"
	"testing"
)

func BenchmarkSM2Sign(t *testing.B) {
	t.ReportAllocs()
	msg := []byte("test")
	priv, err := sm2.GenerateKey(rand.Reader) // 生成密钥对
	if err != nil {
		log.Fatal(err)
	}
	sign, err := priv.Sign(rand.Reader, msg, nil) // 签名
	t.ResetTimer()
	t.StartTimer()
	for i := 0; i < t.N; i++ {
		ok := priv.Verify(msg, sign) // 密钥验证
		if !ok {
			t.Fatal("签名失败")
		}

	}
	t.StopTimer()
}
