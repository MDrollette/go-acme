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
	app.Action = func(c *cli.Context) {
		server := server.NewServer()

		if err := server.Start(); nil != err {
			log.Fatalln(err)
		}
	}

	app.Run(os.Args)
}
