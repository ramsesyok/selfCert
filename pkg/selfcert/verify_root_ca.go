package selfcert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Root CA 証明書の内容を検証する関数
func VerifyRootCA(filename string) (*x509.Certificate, error) {
	// ファイルの読み込み
	certPEM, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("証明書ファイルの読み取りに失敗しました: %w", err)
	}

	// PEMデコード
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("証明書ファイルの形式が無効です")
	}

	// 証明書の解析
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("証明書の解析に失敗しました: %w", err)
	}

	// 証明書の内容を表示
	fmt.Printf("Root CA 証明書の内容:\n")
	fmt.Printf("  Organization: %s\n", cert.Subject.Organization)
	fmt.Printf("  CommonName: %s\n", cert.Subject.CommonName)
	fmt.Printf("  Country: %s\n", cert.Subject.Country)
	fmt.Printf("  Province: %s\n", cert.Subject.Province)
	fmt.Printf("  Locality: %s\n", cert.Subject.Locality)
	fmt.Printf("  有効期間: %s 〜 %s\n", cert.NotBefore, cert.NotAfter)

	return cert, nil
}
