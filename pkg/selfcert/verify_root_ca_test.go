package selfcert

import (
	"os"
	"testing"
)

// VerifyRootCAのテスト
func TestVerifyRootCA(t *testing.T) {
	// テスト用のCA証明書を作成する
	err := CreateRootCA(10, "Test Organization", "Test Root CA", "JP", "Tokyo", "Shibuya")
	if err != nil {
		t.Fatalf("ルートCA証明書の作成に失敗しました: %v", err)
	}

	// VerifyRootCA 関数をテスト
	cert, err := VerifyRootCA("ca.cert")
	if err != nil {
		t.Fatalf("VerifyRootCAの実行に失敗しました: %v", err)
	}

	// 証明書の内容を確認
	if cert.Subject.Organization[0] != "Test Organization" {
		t.Errorf("Organizationが一致しません: %v", cert.Subject.Organization[0])
	}
	if cert.Subject.CommonName != "Test Root CA" {
		t.Errorf("CommonNameが一致しません: %v", cert.Subject.CommonName)
	}
	if cert.Subject.Country[0] != "JP" {
		t.Errorf("Countryが一致しません: %v", cert.Subject.Country[0])
	}
	if cert.Subject.Province[0] != "Tokyo" {
		t.Errorf("Provinceが一致しません: %v", cert.Subject.Province[0])
	}
	if cert.Subject.Locality[0] != "Shibuya" {
		t.Errorf("Localityが一致しません: %v", cert.Subject.Locality[0])
	}

	// テスト後のクリーンアップ
	os.Remove("ca.cert")
	os.Remove("ca.key")
}
