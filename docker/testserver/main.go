package main

import (
	"flag"

	"github.com/webx-top/echo/defaults"
	"github.com/webx-top/echo/engine/standard"
)

// go run ./docker/testserver/main.go --listen ":4444"

var listenAddr string

func main() {
	flag.StringVar(&listenAddr, `listen`, `:4444`, `--listen ":4444"`)
	flag.Parse()

	defaults.Run(standard.New(listenAddr))
}
