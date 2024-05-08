// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"time"

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
	jsonFormat := func(m map[string]any) string {
		jsonData, err := json.Marshal(m)
		if err != nil {
			log.Println(err)
		}
		return string(jsonData)
	}
	templates := make(map[string]*template.Template)

	parsedReport, err := template.New(tmplReportName+".html").Funcs(template.FuncMap{
		"getStatuses":        rule.Statuses,
		"icon":               rule.GetStatusIcon,
		"time":               convTimeFunc,
		"jsonFormat":         jsonFormat,
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
		"icon":                     rule.GetStatusIcon,
		"time":                     convTimeFunc,
		"jsonFormat":               jsonFormat,
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
		"icon":                          rule.GetStatusIcon,
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
