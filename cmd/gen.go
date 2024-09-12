/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:   "gen",
	Short: "自己署名のルート認証局証明書・サーバ証明書作成ツール",
	Long: `本ツールは、自己署名のルート認証局証明書・サーバ証明書を作成します.

1. 自己署名のルート認証局証明書を作成します.
	% selfCert gen ca
	これにより、"ca.key" と "ca.cert" が、生成されます.
	生成された"ca.key" と "ca.cert"は、サーバ証明書作成時に利用します.

2. サーバ証明書を作成します.
	% selfCert gen cert
	"ca.key" と "ca.cert"をもとにサーバ証明書を作成します.
	"server-key.pem","server-csr.pem","server-cert.pem" が、生成されます.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("gen called")
	},
}

func init() {
	cobra.MousetrapHelpText = ""
	rootCmd.AddCommand(genCmd)
}
