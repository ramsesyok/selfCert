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
)

// サーバ証明書の作成
func CreateServerCert(daysValid int, org, cn, country, province, locality string) error {
	// 鍵の生成
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// 証明書署名要求（CSR）のテンプレート
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
	}

	// Country が指定されている場合のみセット
	if country != "" {
		csrTemplate.Subject.Country = []string{country}
	}

	// Province が指定されている場合のみセット
	if province != "" {
		csrTemplate.Subject.Province = []string{province}
	}

	// Locality が指定されている場合のみセット
	if locality != "" {
		csrTemplate.Subject.Locality = []string{locality}
	}

	// CSRの生成
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, priv)
	if err != nil {
		return err
	}

	// CSRをファイルに保存
	csrOut, err := os.Create("server-csr.pem")
	if err != nil {
		return err
	}
	pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	csrOut.Close()

	// ルートCAの秘密鍵と証明書を読み込む
	caCertPEM, err := os.ReadFile("ca.cert")
	if err != nil {
		return err
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return err
	}

	caKeyPEM, err := os.ReadFile("ca.key")
	if err != nil {
		return err
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caPriv, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return err
	}

	// サーバ証明書のテンプレート
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}

	certTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{org},
			CommonName:   cn,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, daysValid),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	// Country が指定されている場合のみセット
	if country != "" {
		certTemplate.Subject.Country = []string{country}
	}

	// Province が指定されている場合のみセット
	if province != "" {
		certTemplate.Subject.Province = []string{province}
	}

	// Locality が指定されている場合のみセット
	if locality != "" {
		certTemplate.Subject.Locality = []string{locality}
	}

	// サーバ証明書の生成
	certDER, err := x509.CreateCertificate(rand.Reader, &certTemplate, caCert, &priv.PublicKey, caPriv)
	if err != nil {
		return err
	}

	// サーバ証明書と秘密鍵を保存
	certOut, err := os.Create("server-cert.pem")
	if err != nil {
		return err
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certOut.Close()

	keyOut, err := os.Create("server-key.pem")
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()

	return nil
}
