package main

import (
	"os"

	"github.com/MDrollette/go-acme/cmd"
	"github.com/codegangsta/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "acme"
	app.Version = "0.1.0"
	app.Usage = "A Go implementation of the ACME protocol."
	app.Flags = []cli.Flag{}
	app.Commands = []cli.Command{
		cmd.NewServerCommand(),
	}

	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
