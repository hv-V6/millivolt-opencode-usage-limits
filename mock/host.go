// Package mock provides an in-process Host for plugin tests and conformance
// runs. It enforces the same capability and byte bounds the core host must.
package mock

import (
	"strings"
	"sync"

	v1 "github.com/LLM-4-People/millivolt-plugin-sdk/abi/v1"
)

// Host records every host call and every denial for assertions.
type Host struct {
	mu            sync.Mutex
	granted       map[string]bool
	event         v1.Event
	calls         []string
	denials       []string
	metrics       []v1.Metric
	tools         []v1.ToolDescriptor
	panels        []v1.UIPanel
	logs          []v1.LogEntry
	fetchRequest  v1.HTTPFetchRequest
	fetchResponse *v1.HTTPFetchResponse
}

// New grants exactly the named capabilities.
func New(capabilities ...string) *Host {
	granted := make(map[string]bool, len(capabilities))
	for _, capability := range capabilities {
		granted[capability] = true
	}
	return &Host{granted: granted}
}

// SetEvent installs the event returned by ReadRecord/ReadConfigView.
func (h *Host) SetEvent(event v1.Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.event = event
}

func (h *Host) allow(capability, call string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, call)
	if !h.granted[capability] {
		h.denials = append(h.denials, call+":"+capability)
		return false
	}
	return true
}

// Calls returns a snapshot of host-call names in order.
func (h *Host) Calls() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.calls...)
}

// Denials returns a snapshot of capability denials in order.
func (h *Host) Denials() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.denials...)
}

// Metrics returns a snapshot of accepted metric emissions.
func (h *Host) Metrics() []v1.Metric {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]v1.Metric, len(h.metrics))
	copy(out, h.metrics)
	return out
}

// Logs returns a snapshot of accepted log entries.
func (h *Host) Logs() []v1.LogEntry {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]v1.LogEntry, len(h.logs))
	copy(out, h.logs)
	return out
}

// Tools returns a snapshot of accepted tool declarations.
func (h *Host) Tools() []v1.ToolDescriptor {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]v1.ToolDescriptor(nil), h.tools...)
}

// Panels returns a snapshot of accepted UI panel declarations.
func (h *Host) Panels() []v1.UIPanel {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]v1.UIPanel(nil), h.panels...)
}

// Log implements guest.Host.
func (h *Host) Log(level, message string) bool {
	if !h.allow("log", "log") || len(message) > v1.MaxLogBytes {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logs = append(h.logs, v1.LogEntry{Level: level, Message: message})
	return true
}

// EmitMetric implements guest.Host.
func (h *Host) EmitMetric(name string, value float64, labels map[string]string) bool {
	if !h.allow("emit_metric", "emit_metric") || len(name) > v1.MaxNameBytes {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.metrics = append(h.metrics, v1.Metric{Name: name, Value: value, Labels: labels})
	return true
}

// ReadRecord implements guest.Host.
func (h *Host) ReadRecord() (*v1.Record, bool) {
	if !h.allow("read:records", "read_record") || h.event.Record == nil {
		return nil, false
	}
	record := *h.event.Record
	return &record, true
}

// ReadConfigView implements guest.Host.
func (h *Host) ReadConfigView() (*v1.ConfigView, bool) {
	if !h.allow("read:config", "read_config_view") || h.event.Config == nil {
		return nil, false
	}
	view := *h.event.Config
	view.Values = make(map[string]string, len(h.event.Config.Values))
	for key, value := range h.event.Config.Values {
		view.Values[key] = value
	}
	return &view, true
}

// DeclareTool implements guest.Host.
func (h *Host) DeclareTool(name, description, capability string) bool {
	if !h.allow("declare_tool", "declare_tool") ||
		len(name) > v1.MaxNameBytes || len(description) > v1.MaxLogBytes {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tools = append(h.tools, v1.ToolDescriptor{Name: name, Description: description, Capability: capability})
	return true
}

// DeclareUIPanel implements guest.Host.
func (h *Host) DeclareUIPanel(id, title string, data map[string]string) bool {
	if !h.allow("declare_ui_panel", "declare_ui_panel") ||
		len(id) > v1.MaxNameBytes || len(title) > v1.MaxNameBytes {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.panels = append(h.panels, v1.UIPanel{ID: id, Title: title, Data: data})
	return true
}

// SetHTTPFetchResponse installs the bounded result returned by HTTPFetch.
func (h *Host) SetHTTPFetchResponse(resp *v1.HTTPFetchResponse) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fetchResponse = resp
}

// LastHTTPFetchRequest returns the most recent request for assertions.
func (h *Host) LastHTTPFetchRequest() v1.HTTPFetchRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.fetchRequest
}

// HTTPFetch implements guest.Host.
func (h *Host) HTTPFetch(req v1.HTTPFetchRequest) (*v1.HTTPFetchResponse, bool) {
	if !h.allow(v1.CapabilityHTTPFetch, "http_fetch") || h.fetchResponse == nil {
		return nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fetchRequest = req
	out := *h.fetchResponse
	return &out, true
}

// HasOnlyCapabilities reports whether the host was granted no capabilities
// outside the named set. Used by conformance to prove deny-by-default.
func (h *Host) HasOnlyCapabilities(names ...string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.granted) != len(names) {
		return false
	}
	for _, name := range names {
		if !h.granted[name] {
			return false
		}
	}
	return true
}

// StringList joins a list for compact failure messages.
func StringList(values []string) string { return strings.Join(values, ",") }
