package cmd

import (
	"log"

	"github.com/MDrollette/go-acme/server"
	"github.com/codegangsta/cli"
)

func NewServerCommand() cli.Command {
	return cli.Command{
		Name:   "serve",
		Usage:  "Start an ACME server",
		Action: serverAction,
		Flags: []cli.Flag{
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
			cli.StringFlag{
				Name:  "addr",
				Value: "127.0.0.1:9999",
				Usage: "ip and port to listen on",
			},
		},
	}
}

func serverAction(c *cli.Context) {
	service := server.NewService(nil)
	err := service.InitCertificateAuthority()
	if nil != err {
		log.Fatalln(err)
	}

	server := server.NewServer(service)
	server.Addr = c.String("addr")
	server.CertPath = c.String("cert")
	server.KeyPath = c.String("key")

	if err := server.Start(); nil != err {
		log.Fatalln(err)
	}
}
