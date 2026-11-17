// Package analyzer is a reference v1 plugin: it counts failed requests by
// provider and emits one bounded metric per event.
package analyzer

import (
	"fmt"

	v1 "github.com/LLM-4-People/millivolt-plugin-sdk/abi/v1"
)

type Analyzer struct{}

func (Analyzer) Init() error { return nil }

func (Analyzer) Handle(event v1.Event) (*v1.Response, error) {
	if event.Type != v1.EventRequestRecorded || event.Record == nil {
		return &v1.Response{}, nil
	}
	resp := &v1.Response{}
	if event.Record.ErrorType != "" {
		resp.Metrics = append(resp.Metrics, v1.Metric{
			Name:   "plugin.analyzer.failed_requests",
			Value:  1,
			Labels: map[string]string{"provider": event.Record.Provider, "error": event.Record.ErrorType},
		})
		resp.Logs = append(resp.Logs, v1.LogEntry{
			Level:   "warn",
			Message: fmt.Sprintf("failed request %s on %s", event.Record.ID, event.Record.Provider),
		})
	}
	return resp, nil
}

func (Analyzer) Shutdown() error { return nil }
