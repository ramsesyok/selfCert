package selfcert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"

	"github.com/spf13/viper"
)

func CreateRootCA(yearsValid int, org, cn, country, province, locality string) error {
	certFile := viper.GetString("RootCA.file.cert")
	keyFile := viper.GetString("RootCA.file.key")
	// 鍵の生成
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// シリアル番号
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	// 証明書のテンプレート
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(yearsValid, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	// Country が指定されている場合のみセット
	if country != "" {
		tmpl.Subject.Country = []string{country}
	}

	// Province が指定されている場合のみセット
	if province != "" {
		tmpl.Subject.Province = []string{province}
	}

	// Locality が指定されている場合のみセット
	if locality != "" {
		tmpl.Subject.Locality = []string{locality}
	}

	// 自己署名証明書の生成
	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// 秘密鍵と証明書を保存
	//certOut, err := os.Create("ca.cert")
	certOut, err := os.Create(certFile)
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyOut, err := os.Create(keyFile)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}
