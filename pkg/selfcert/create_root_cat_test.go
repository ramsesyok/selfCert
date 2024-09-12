package selfcert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

// ルートCA証明書作成のテスト
func TestCreateRootCA(t *testing.T) {
	// テスト用のパラメータ
	yearsValid := 10
	org := "Test Organization"
	cn := "Test Root CA"
	country := "JP"
	province := "Tokyo"
	locality := "Shibuya"

	// 関数の呼び出し
	err := CreateRootCA(yearsValid, org, cn, country, province, locality)
	if err != nil {
		t.Fatalf("ルートCA証明書の作成に失敗しました: %v", err)
	}

	// 証明書ファイルの確認
	if _, err := os.Stat("ca.cert"); os.IsNotExist(err) {
		t.Errorf("ca.certファイルが存在しません")
	}

	// 秘密鍵ファイルの確認
	if _, err := os.Stat("ca.key"); os.IsNotExist(err) {
		t.Errorf("ca.keyファイルが存在しません")
	}

	// 証明書内容のチェック
	certPEM, err := os.ReadFile("ca.cert")
	if err != nil {
		t.Fatalf("ca.certの読み取りに失敗しました: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("ca.certは有効な証明書ではありません")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("ca.certのパースに失敗しました: %v", err)
	}

	// 証明書フィールドの検証
	if caCert.Subject.Organization[0] != org {
		t.Errorf("証明書のOrganizationが間違っています: %v", caCert.Subject.Organization[0])
	}
	if caCert.Subject.CommonName != cn {
		t.Errorf("証明書のCommonNameが間違っています: %v", caCert.Subject.CommonName)
	}
	if caCert.Subject.Country[0] != country {
		t.Errorf("証明書のCountryが間違っています: %v", caCert.Subject.Country[0])
	}

	// テスト後のクリーンアップ
	os.Remove("ca.cert")
	os.Remove("ca.key")
}

// ルートCA証明書作成のテスト（空白のprovinceとlocality）
func TestCreateRootCAWithEmptyFields(t *testing.T) {
	// テスト用のパラメータ（provinceとlocalityが空白）
	yearsValid := 10
	org := "Test Organization"
	cn := "Test Root CA"
	country := "JP"
	province := "" // 空白
	locality := "" // 空白

	// 関数の呼び出し
	err := CreateRootCA(yearsValid, org, cn, country, province, locality)
	if err != nil {
		t.Fatalf("ルートCA証明書の作成に失敗しました: %v", err)
	}

	// 証明書ファイルの確認
	if _, err := os.Stat("ca.cert"); os.IsNotExist(err) {
		t.Errorf("ca.certファイルが存在しません")
	}

	// 証明書内容のチェック
	certPEM, err := os.ReadFile("ca.cert")
	if err != nil {
		t.Fatalf("ca.certの読み取りに失敗しました: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("ca.certは有効な証明書ではありません")
	}

	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("ca.certのパースに失敗しました: %v", err)
	}

	// 証明書フィールドの検証
	if caCert.Subject.Organization[0] != org {
		t.Errorf("証明書のOrganizationが間違っています: %v", caCert.Subject.Organization[0])
	}
	if caCert.Subject.CommonName != cn {
		t.Errorf("証明書のCommonNameが間違っています: %v", caCert.Subject.CommonName)
	}
	if len(caCert.Subject.Province) > 0 {
		t.Errorf("証明書のProvinceが空白であるべきです: %v", caCert.Subject.Province[0])
	}
	if len(caCert.Subject.Locality) > 0 {
		t.Errorf("証明書のLocalityが空白であるべきです: %v", caCert.Subject.Locality[0])
	}

	// テスト後のクリーンアップ
	os.Remove("ca.cert")
	os.Remove("ca.key")
}
