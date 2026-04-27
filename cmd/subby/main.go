package main

import (
	"os"

	"github.com/Jvr2022/subby/pkg/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
