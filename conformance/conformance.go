// Package conformance is the shared behavioral suite every guest adapter must
// pass. It tests observable outcomes, not SDK wiring.
package conformance

import (
	"fmt"
	"strings"

	v1 "github.com/LLM-4-People/millivolt-plugin-sdk/abi/v1"
	"github.com/LLM-4-People/millivolt-plugin-sdk/guest/go"
	"github.com/LLM-4-People/millivolt-plugin-sdk/mock"
)

// Failure is one failed conformance case.
type Failure struct {
	Case   string
	Detail string
}

func failedRecord() v1.Event {
	return v1.Event{
		Type: v1.EventRequestRecorded,
		Seq:  1,
		Record: &v1.Record{
			ID:           "req-1",
			Status:       429,
			Provider:     "example.test",
			Model:        "model-a",
			Client:       "pi",
			ErrorType:    "rate_limit",
			InputTokens:  10,
			OutputTokens: 2,
		},
	}
}

// Run drives a fresh guest from factory through every v1 case. The factory is
// called once per case so state cannot leak between them.
func Run(factory func() guest.Guest) []Failure {
	var failures []Failure
	add := func(name string, detail string) {
		failures = append(failures, Failure{Case: name, Detail: detail})
	}

	g := factory()
	host := mock.New("log", "emit_metric", "declare_ui_panel")
	host.SetEvent(failedRecord())
	if err := g.Init(); err != nil {
		add("lifecycle", fmt.Sprintf("Init: %v", err))
	}
	if _, err := guest.Run(g, host, failedRecord()); err != nil {
		add("failed record", fmt.Sprintf("Run: %v", err))
	}
	if err := g.Shutdown(); err != nil {
		add("lifecycle", fmt.Sprintf("Shutdown: %v", err))
	}
	if len(host.Metrics()) < 1 {
		add("failed record", fmt.Sprintf("metrics = %d, want at least 1", len(host.Metrics())))
	}
	if len(host.Logs()) < 1 {
		add("failed record", fmt.Sprintf("logs = %d, want at least 1", len(host.Logs())))
	}
	if len(host.Logs()) != 1 {
		add("failed record", fmt.Sprintf("logs = %d, want 1", len(host.Logs())))
	}
	if denials := host.Denials(); len(denials) != 0 {
		add("failed record", "unexpected denials: "+mock.StringList(denials))
	}

	g = factory()
	denied := mock.New("log")
	denied.SetEvent(failedRecord())
	if _, err := guest.Run(g, denied, failedRecord()); err != nil {
		add("denied capability", fmt.Sprintf("Run must tolerate denial: %v", err))
	}
	if len(denied.Metrics()) != 0 {
		add("denied capability", "metric was emitted without emit_metric")
	}
	if !strings.Contains(mock.StringList(denied.Denials()), "emit_metric") {
		add("denied capability", "no denial recorded for emit_metric")
	}

	g = factory()
	quiet := mock.New("log", "emit_metric", "read:records", "read:config", "declare_tool", "declare_ui_panel")
	if _, err := guest.Run(g, quiet, v1.Event{Type: v1.EventConfigChanged, Config: &v1.ConfigView{SchemaVersion: 1}}); err != nil {
		add("non-record event", fmt.Sprintf("Run: %v", err))
	}
	if calls := quiet.Calls(); len(calls) != 0 {
		add("non-record event", "unexpected host calls: "+mock.StringList(calls))
	}

	tooMany := &oversizedGuest{}
	bounded := mock.New("log")
	if _, err := guest.Run(tooMany, bounded, failedRecord()); err == nil {
		add("response cap", "oversized response was accepted")
	}
	if len(bounded.Calls()) != 0 {
		add("response cap", "host calls ran before cap validation")
	}

	return failures
}

type oversizedGuest struct{}

func (oversizedGuest) Init() error     { return nil }
func (oversizedGuest) Shutdown() error { return nil }
func (oversizedGuest) Handle(v1.Event) (*v1.Response, error) {
	logs := make([]v1.LogEntry, v1.MaxLogs+1)
	for i := range logs {
		logs[i] = v1.LogEntry{Level: "info", Message: "x"}
	}
	return &v1.Response{Logs: logs}, nil
}
