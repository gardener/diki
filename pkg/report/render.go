// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"maps"
	"slices"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/gardener/diki/pkg/rule"
)

const (
	tmplReportName           = "report"
	tmplReportPath           = "templates/html/report.html"
	tmplMergedReportName     = "merged_report"
	tmplMergedReportPath     = "templates/html/merged_report.html"
	tmplDifferenceReportName = "difference_report"
	tmplDifferenceReportPath = "templates/html/difference_report.html"
	tmplStylesPath           = "templates/html/_styles.tpl"
)

var (
	//go:embed templates/html/*
	files embed.FS
)

// HTMLRenderer renders Diki reports in html format.
type HTMLRenderer struct {
	templates map[string]*template.Template
}

// NewHTMLRenderer creates a HTMLRenderer.
func NewHTMLRenderer() (*HTMLRenderer, error) {
	convTimeFunc := func(time time.Time) string {
		return time.Format("01-02-2006")
	}
	add := func(a, b int) int {
		return a + b
	}
	keyExists := func(m map[string]string, k string) bool {
		_, ok := m[k]
		return ok
	}
	yamlFormat := func(m map[string]any) string {
		yaml, err := yaml.Marshal(m)
		if err != nil {
			return err.Error()
		}
		return string(yaml)
	}
	templates := make(map[string]*template.Template)

	parsedReport, err := template.New(tmplReportName+".html").Funcs(template.FuncMap{
		"getStatuses":        rule.Statuses,
		"statusIcon":         rule.StatusIcon,
		"statusDescription":  rule.StatusDescription,
		"time":               convTimeFunc,
		"yamlFormat":         yamlFormat,
		"rulesetSummaryText": rulesetSummaryText,
		"rulesWithStatus":    rulesWithStatus,
		"sortedMapKeys":      sortedKeys[string],
	}).ParseFS(files, tmplReportPath, tmplStylesPath)
	if err != nil {
		return nil, err
	}
	templates[tmplReportName] = parsedReport

	parsedMergedReport, err := template.New(tmplMergedReportName+".html").Funcs(template.FuncMap{
		"getStatuses":              rule.Statuses,
		"statusIcon":               rule.StatusIcon,
		"statusDescription":        rule.StatusDescription,
		"time":                     convTimeFunc,
		"yamlFormat":               yamlFormat,
		"mergedMetadataTexts":      metadataTextForMergedProvider,
		"mergedRulesetSummaryText": mergedRulesetSummaryText,
		"mergedRulesWithStatus":    mergedRulesWithStatus,
		"sortedMapKeys":            sortedKeys[string],
	}).ParseFS(files, tmplMergedReportPath, tmplStylesPath)
	if err != nil {
		return nil, err
	}
	templates[tmplMergedReportName] = parsedMergedReport

	parsedDifferenceReport, err := template.New(tmplDifferenceReportName+".html").Funcs(template.FuncMap{
		"add":                           add,
		"getStatuses":                   rule.Statuses,
		"statusIcon":                    rule.StatusIcon,
		"statusDescription":             rule.StatusDescription,
		"rulesetDiffAddedSummaryText":   rulesetDiffAddedSummaryText,
		"rulesetDiffRemovedSummaryText": rulesetDiffRemovedSummaryText,
		"keyExists":                     keyExists,
		"getAttrString":                 getProviderDiffIDText,
		"sortedMapKeys":                 sortedKeys[string],
	}).ParseFS(files, tmplDifferenceReportPath, tmplStylesPath)
	if err != nil {
		return nil, err
	}
	templates[tmplDifferenceReportName] = parsedDifferenceReport

	return &HTMLRenderer{
		templates: templates,
	}, nil
}

// Render writes a Diki report in html format into the passed writer.
func (r *HTMLRenderer) Render(w io.Writer, report any) error {
	switch rep := report.(type) {
	case *Report:
		return r.templates[tmplReportName].Execute(w, rep)
	case *MergedReport:
		return r.templates[tmplMergedReportName].Execute(w, rep)
	case *DifferenceReportsWrapper:
		return r.templates[tmplDifferenceReportName].Execute(w, rep)
	default:
		return fmt.Errorf("unsupported report type: %T", report)
	}
}

func sortedKeys[T any](m map[string]T) []string {
	return slices.Sorted(maps.Keys(m))
}
