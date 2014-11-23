package main

import (
	"log"
	"os"

	"github.com/MDrollette/go-acme/server"
	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "serve"
	app.Usage = "Start an ACME server."
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "cert",
			Value: "ca_cert.pem",
			Usage: "CA certificate",
		},
		cli.StringFlag{
			Name:  "key",
			Value: "ca_key.pem",
			Usage: "CA private key",
		},
	}
	app.Action = func(c *cli.Context) {
		service := server.NewService(nil)
		err := service.InitCertificateAuthority()
		if nil != err {
			log.Fatalln(err)
		}

		server := server.NewServer(service)
		server.Addr = "127.0.0.1:9999"
		server.CertPath = c.String("cert")
		server.KeyPath = c.String("key")

		if err := server.Start(); nil != err {
			log.Fatalln(err)
		}
	}

	app.Run(os.Args)
}
