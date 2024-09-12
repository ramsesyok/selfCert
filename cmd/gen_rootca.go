/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"masc.co.jp/m98004/selfCert/pkg/selfcert"
)

// genRootCACmd represents the rootca command
var genRootCACmd = &cobra.Command{
	Use:   "rootca",
	Short: "自己署名のルート認証局証明書の作成",
	Long: `自己署名のルート認証局証明書を作成します。

以下の手順が処理が実行され、ca.key / ca.cert を出力します.
 1. 自己署名のルート認証局証明書の秘密鍵を作成(ca.key)
 2. 自己署名のルート認証局証明書の秘密鍵(ca.key)を使って、自己署名のルート認証局証明書の証明書署名要求を作成
 3. 自己署名のルート認証局証明書を作成(ca.cert)

 自己署名のルート認証局証明書の有効期限、組織名等の設定は、selfCert.yaml内に記載します. `,
	Run: func(cmd *cobra.Command, args []string) {
		yearsValid := viper.GetInt("RootCA.duration")
		org := viper.GetString("RootCA.Organization")
		cn := viper.GetString("RootCA.CommonName")
		country := viper.GetString("RootCA.Country")
		province := viper.GetString("RootCA.Province")
		locality := viper.GetString("RootCA.Locality")
		selfcert.CreateRootCA(yearsValid, org, cn, country, province, locality)
	},
}

func init() {
	genCmd.AddCommand(genRootCACmd)
}
