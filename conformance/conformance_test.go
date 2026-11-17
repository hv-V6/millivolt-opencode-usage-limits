package conformance

import (
	"testing"

	"github.com/LLM-4-People/millivolt-plugin-sdk/examples/analyzer"
	"github.com/LLM-4-People/millivolt-plugin-sdk/guest/go"
)

func TestReferenceAnalyzerPasses(t *testing.T) {
	failures := Run(func() guest.Guest { return analyzer.Analyzer{} })
	for _, failure := range failures {
		t.Errorf("%s: %s", failure.Case, failure.Detail)
	}
}
