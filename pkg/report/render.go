// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"time"

	"github.com/gardener/diki/pkg/rule"
)

const (
	tmplReportName       = "report"
	tmplReportPath       = "templates/html/report.html"
	tmplMergedReportName = "merged_report"
	tmplMergedReportPath = "templates/html/merged_report.html"
	tmplStylesPath       = "templates/html/_styles.tpl"
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
	templates := make(map[string]*template.Template)

	parsedReport, err := template.New(tmplReportName+".html").Funcs(template.FuncMap{
		"Statuses":           rule.Statuses,
		"Icon":               rule.GetStatusIcon,
		"Time":               convTimeFunc,
		"RulesetSummaryText": rulesetSummaryText,
		"RulesWithStatus":    rulesWithStatus,
	}).ParseFS(files, tmplReportPath, tmplStylesPath)
	if err != nil {
		return nil, err
	}
	templates[tmplReportName] = parsedReport

	parsedMergedReport, err := template.New(tmplMergedReportName+".html").Funcs(template.FuncMap{
		"Statuses":                 rule.Statuses,
		"Icon":                     rule.GetStatusIcon,
		"Time":                     convTimeFunc,
		"MergedMetadataTexts":      metadataTextForMergedProvider,
		"MergedRulesetSummaryText": mergedRulesetSummaryText,
		"MergedRulesWithStatus":    mergedRulesWithStatus,
	}).ParseFS(files, tmplMergedReportPath, tmplStylesPath)
	if err != nil {
		return nil, err
	}
	templates[tmplMergedReportName] = parsedMergedReport

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
	default:
		return fmt.Errorf("unsupported report type: %T", report)
	}
}
