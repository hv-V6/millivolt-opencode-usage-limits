// Command analyzer is a Go-native host for the reference plugin. The core
// WASM adapter supplies the same guest lifecycle in production.
package main

import (
	"fmt"

	v1 "github.com/LLM-4-People/millivolt-plugin-sdk/abi/v1"
	"github.com/LLM-4-People/millivolt-plugin-sdk/examples/analyzer"
	"github.com/LLM-4-People/millivolt-plugin-sdk/guest/go"
	"github.com/LLM-4-People/millivolt-plugin-sdk/mock"
)

func main() {
	g := analyzer.Analyzer{}
	if err := g.Init(); err != nil {
		panic(err)
	}
	host := mock.New("log", "emit_metric")
	response, err := guest.Run(g, host, v1.Event{
		Type:   v1.EventRequestRecorded,
		Record: &v1.Record{ID: "demo", Provider: "example.test", ErrorType: "rate_limit"},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("metrics=%d logs=%d denials=%d\n", len(response.Metrics), len(response.Logs), len(host.Denials()))
}
