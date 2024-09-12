package selfcert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// サーバ証明書作成のテスト
func TestCreateServerCert(t *testing.T) {
	// まずはルートCAを作成する
	err := CreateRootCA(10, "Test Organization", "Test Root CA", "JP", "Tokyo", "Shibuya")
	if err != nil {
		t.Fatalf("ルートCA証明書の作成に失敗しました: %v", err)
	}

	// テスト用のパラメータ
	daysValid := 365
	org := "Test Server Organization"
	cn := "Test Server"
	country := "JP"
	province := "Osaka"
	locality := "Namba"

	// 関数の呼び出し
	err = CreateServerCert(daysValid, org, cn, country, province, locality)
	if err != nil {
		t.Fatalf("サーバ証明書の作成に失敗しました: %v", err)
	}

	// 証明書ファイルの確認
	if _, err := os.Stat("server-cert.pem"); os.IsNotExist(err) {
		t.Errorf("server-cert.pemファイルが存在しません")
	}

	// CSRファイルの確認
	if _, err := os.Stat("server-csr.pem"); os.IsNotExist(err) {
		t.Errorf("server-csr.pemファイルが存在しません")
	}

	// 秘密鍵ファイルの確認
	if _, err := os.Stat("server-key.pem"); os.IsNotExist(err) {
		t.Errorf("server-key.pemファイルが存在しません")
	}

	// サーバ証明書内容のチェック
	certPEM, err := os.ReadFile("server-cert.pem")
	if err != nil {
		t.Fatalf("server-cert.pemの読み取りに失敗しました: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("server-cert.pemは有効な証明書ではありません")
	}

	serverCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("server-cert.pemのパースに失敗しました: %v", err)
	}

	// 証明書フィールドの検証
	if serverCert.Subject.Organization[0] != org {
		t.Errorf("証明書のOrganizationが間違っています: %v", serverCert.Subject.Organization[0])
	}
	if serverCert.Subject.CommonName != cn {
		t.Errorf("証明書のCommonNameが間違っています: %v", serverCert.Subject.CommonName)
	}
	if serverCert.Subject.Country[0] != country {
		t.Errorf("証明書のCountryが間違っています: %v", serverCert.Subject.Country[0])
	}
	if serverCert.Subject.Province[0] != province {
		t.Errorf("証明書のProvinceが間違っています: %v", serverCert.Subject.Province[0])
	}
	if serverCert.Subject.Locality[0] != locality {
		t.Errorf("証明書のLocalityが間違っています: %v", serverCert.Subject.Locality[0])
	}

	// テスト後のクリーンアップ
	os.Remove("server-cert.pem")
	os.Remove("server-csr.pem")
	os.Remove("server-key.pem")
	os.Remove("ca.cert")
	os.Remove("ca.key")
}

// provinceとlocalityが空の場合のサーバ証明書作成テスト
func TestCreateServerCertWithEmptyFields(t *testing.T) {
	// まずはルートCAを作成する
	err := CreateRootCA(10, "Test Organization", "Test Root CA", "JP", "", "")
	if err != nil {
		t.Fatalf("ルートCA証明書の作成に失敗しました: %v", err)
	}

	// テスト用のパラメータ（provinceとlocalityが空）
	daysValid := 365
	org := "Test Server Organization"
	cn := "Test Server"
	country := "JP"
	province := "" // 空白
	locality := "" // 空白

	// 関数の呼び出し
	err = CreateServerCert(daysValid, org, cn, country, province, locality)
	if err != nil {
		t.Fatalf("サーバ証明書の作成に失敗しました: %v", err)
	}

	// 証明書ファイルの確認
	if _, err := os.Stat("server-cert.pem"); os.IsNotExist(err) {
		t.Errorf("server-cert.pemファイルが存在しません")
	}

	// サーバ証明書内容のチェック
	certPEM, err := os.ReadFile("server-cert.pem")
	if err != nil {
		t.Fatalf("server-cert.pemの読み取りに失敗しました: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("server-cert.pemは有効な証明書ではありません")
	}

	serverCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("server-cert.pemのパースに失敗しました: %v", err)
	}

	// サーバ証明書フィールドの検証
	if serverCert.Subject.Organization[0] != org {
		t.Errorf("証明書のOrganizationが間違っています: %v", serverCert.Subject.Organization[0])
	}
	if serverCert.Subject.CommonName != cn {
		t.Errorf("証明書のCommonNameが間違っています: %v", serverCert.Subject.CommonName)
	}
	if serverCert.Subject.Country[0] != country {
		t.Errorf("証明書のCountryが間違っています: %v", serverCert.Subject.Country[0])
	}
	if len(serverCert.Subject.Province) > 0 {
		t.Errorf("証明書のProvinceが空であるべきです: %v", serverCert.Subject.Province[0])
	}
	if len(serverCert.Subject.Locality) > 0 {
		t.Errorf("証明書のLocalityが空であるべきです: %v", serverCert.Subject.Locality[0])
	}

	// テスト後のクリーンアップ
	os.Remove("server-cert.pem")
	os.Remove("server-csr.pem")
	os.Remove("server-key.pem")
	os.Remove("ca.cert")
	os.Remove("ca.key")
}
