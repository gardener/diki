// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/gardener/diki/pkg/rule"
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
	tmplFiles, err := fs.ReadDir(files, "templates/html")
	if err != nil {
		return nil, err
	}

	templates := make(map[string]*template.Template)
	for _, tmpl := range tmplFiles {
		if tmpl.IsDir() {
			continue
		}
		if !strings.HasSuffix(tmpl.Name(), ".html") {
			continue
		}

		pt, err := template.New(tmpl.Name()).Funcs(template.FuncMap{
			"Statuses": rule.Statuses,
			"Icon":     rule.GetStatusIcon,
			"Time": func(time time.Time) string {
				return time.Format("01-02-2006")
			},
			"RulesetSummaryText": rulesetSummaryText,
			"RulesWithStatus":    rulesWithStatus,
		}).ParseFS(files, "templates/html/"+tmpl.Name(), "templates/html/_styles.tpl")
		if err != nil {
			return nil, err
		}
		templates[strings.TrimSuffix(tmpl.Name(), ".html")] = pt
	}
	return &HTMLRenderer{
		templates: templates,
	}, nil
}

// Render writes a Diki report in html format into the passed writer.
func (r *HTMLRenderer) Render(w io.Writer, report any) error {
	switch rep := report.(type) {
	case *Report:
		return r.templates["report"].Execute(w, rep)
	default:
		return fmt.Errorf("unsupported report type: %T", rep)
	}
}
