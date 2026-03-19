package main

import (
	"os"

	"github.com/octokraft/agent-vault/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
