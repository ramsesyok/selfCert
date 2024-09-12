/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"masc.co.jp/m98004/selfCert/pkg/selfcert"
)

// genCertCmd represents the cert command
var genCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "サーバ証明書の作成",
	Long: `自己署名のルート認証局証明書をもとに、サーバ証明書を作成します.

以下の手順が処理が実行され、server-cert.pem / server-key.pem を出力します.
1. サーバ証明書の秘密鍵を作成(server-key.pem)
2. サーバ証明書の秘密鍵(server-key.pem)を使って、サーバ証明書のの証明書署名要求を作成
3. 自己署名のルート認証局証明書(ca.cert)自己署名のルート認証局証明書の秘密鍵(ca.key)を使ってサーバ証明書を作成(server-cert.pem)

サーバ証明書の有効期限、組織名等の設定は、コマンドライン引数で指定します.`,
	Run: func(cmd *cobra.Command, args []string) {

		daysValid := viper.GetInt("d")
		org, _ := cmd.Flags().GetString("O")
		cn, _ := cmd.Flags().GetString("CN")
		country, _ := cmd.Flags().GetString("C")
		province, _ := cmd.Flags().GetString("P")
		locality, _ := cmd.Flags().GetString("L")
		selfcert.CreateServerCert(daysValid, org, cn, country, province, locality)
	},
}

func init() {
	genCmd.AddCommand(genCertCmd)

	genCertCmd.Flags().String("O", "My Company", "組織名")
	genCertCmd.MarkFlagRequired("O")

	genCertCmd.Flags().String("CN", "www.example.com", "コモンネーム")
	genCertCmd.MarkFlagRequired("CN")

	genCertCmd.Flags().Int("d", 365, "有効期限（日）")
	genCertCmd.MarkFlagRequired("d")

	genCertCmd.Flags().String("C", "JP", "国名")
	genCertCmd.Flags().String("P", "", "県名")
	genCertCmd.Flags().String("L", "", "市区町村名")

}
