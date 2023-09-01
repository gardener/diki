// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/report"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

// NewDikiCommand creates a new command that is used to start Diki.
func NewDikiCommand(ctx context.Context, providerCreateFuncs map[string]provider.ProviderFromConfigFunc) *cobra.Command {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	rootCmd := &cobra.Command{
		Use:   "diki",
		Short: "Diki a \"compliance checker\" or sorts, a detective control framework.",
		Long: `Diki a "compliance checker" or sorts, a detective control framework. 
It is part of the Gardener family, but can be used also on other Kubernetes distros or even on non-Kubernetes environments, 
e.g. to check compliance of your hyperscaler accounts.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	var opts runOptions
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run some rulesets and rules.",
		Long:  `Run allows running rulesets and rules for the given provider(s).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCmd(ctx, providerCreateFuncs, opts)
		},
	}

	addRunFlags(runCmd, &opts)
	rootCmd.AddCommand(runCmd)

	var reportOpts reportOptions
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Report converts output files.",
		Long:  `Report converts output files.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return reportCmd(args, reportOpts)
		},
	}

	addReportFlags(reportCmd, &reportOpts)
	rootCmd.AddCommand(reportCmd)

	return rootCmd
}

func addRunFlags(cmd *cobra.Command, opts *runOptions) {
	cmd.PersistentFlags().StringVar(&opts.configFile, "config", "", "Configuration file for diki containing info about providers and rulesets.")
	cmd.PersistentFlags().BoolVar(&opts.all, "all", false, "If set to true diki will run all rulesets for all known providers.")
	cmd.PersistentFlags().StringVar(&opts.provider, "provider", "", "The provider that should be used to run checks.")
	cmd.PersistentFlags().StringVar(&opts.rulesetID, "ruleset-id", "", "The id of the ruleset that should be run. If provided --ruleset-version should also be set. If both flags are empty all rulesets for the provider will be run.")
	cmd.PersistentFlags().StringVar(&opts.rulesetVersion, "ruleset-version", "", "The version of the ruleset that should be run. If provided --ruleset-id should also be set. If both flags are empty all rulesets for the provider will be run.")
	cmd.PersistentFlags().StringVar(&opts.ruleID, "rule-id", "", "If set only the rule with the provided id will be run.")
}

func addReportFlags(cmd *cobra.Command, opts *reportOptions) {
	cmd.PersistentFlags().StringVar(&opts.output, "output", "html", "Output type.")
}

func reportCmd(args []string, opts reportOptions) error {
	if len(args) != 1 {
		return errors.New("report requires a single filepath argument")
	}

	if opts.output != "html" {
		return fmt.Errorf("unsuported output format: %s", opts.output)
	}

	fileData, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("failed to read file %s:%w", args[0], err)
	}

	// TODO: handle report types
	rep := &report.Report{}
	if err := json.Unmarshal(fileData, rep); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	htlmRenderer, err := report.NewHTMLRenderer()
	if err != nil {
		return fmt.Errorf("failed to initialize renderer: %w", err)
	}

	return htlmRenderer.Render(os.Stdout, rep)
}

func runCmd(ctx context.Context, providerCreateFuncs map[string]provider.ProviderFromConfigFunc, opts runOptions) error {
	dikiConfig, err := readConfig(opts.configFile)
	if err != nil {
		return err
	}

	providers, err := getProvidersFromConfig(dikiConfig, providerCreateFuncs)
	if err != nil {
		return err
	}

	// outputPath := dikiConfig.Output.Path

	if opts.all {
		providerResults := []provider.ProviderResult{}
		for _, p := range providers {
			res, err := p.RunAll(ctx)
			if err != nil {
				return err
			}
			providerResults = append(providerResults, res)
		}

		if dikiConfig.Output != nil && dikiConfig.Output.Path != "" {
			opts := []report.ReportOption{}
			if dikiConfig.Output.MinStatus != "" {
				opts = append(opts, report.MinStatus(dikiConfig.Output.MinStatus))
			}
			rep := report.FromProviderResults(providerResults, opts...)
			return rep.WriteToFile(dikiConfig.Output.Path)
		}
		return nil
	}

	p, ok := providers[opts.provider]
	if !ok {
		return fmt.Errorf("unknown provider: %s", opts.provider)
	}

	switch {
	case opts.rulesetID == "" && opts.rulesetVersion == "":
		// run all rulesets for the provider
		res, err := p.RunAll(ctx)
		if err != nil {
			return err
		}
		providerResults := []provider.ProviderResult{res}

		if dikiConfig.Output != nil && dikiConfig.Output.Path != "" {
			opts := []report.ReportOption{}
			if dikiConfig.Output.MinStatus != "" {
				opts = append(opts, report.MinStatus(dikiConfig.Output.MinStatus))
			}
			rep := report.FromProviderResults(providerResults, opts...)
			return rep.WriteToFile(dikiConfig.Output.Path)
		}
		return nil
	case opts.rulesetID != "" && opts.rulesetVersion == "":
		return errors.New("--ruleset-version should be set along with --ruleset-id")
	case opts.rulesetID == "" && opts.rulesetVersion != "":
		return errors.New("--ruleset-id should be set along with --ruleset-version")
	}

	if opts.ruleID == "" {
		// run the whole ruleset
		res, err := p.RunRuleset(ctx, opts.rulesetID, opts.rulesetVersion)
		if err != nil {
			return err
		}
		providerResults := []provider.ProviderResult{{ProviderID: p.ID(), ProviderName: p.Name(), RulesetResults: []ruleset.RulesetResult{res}}}

		if dikiConfig.Output != nil && dikiConfig.Output.Path != "" {
			opts := []report.ReportOption{}
			if dikiConfig.Output.MinStatus != "" {
				opts = append(opts, report.MinStatus(dikiConfig.Output.MinStatus))
			}
			rep := report.FromProviderResults(providerResults, opts...)
			return rep.WriteToFile(dikiConfig.Output.Path)
		}
		return nil
	}

	return runRule(ctx, p, opts.rulesetID, opts.rulesetVersion, opts.ruleID)
}

// StringOrDefault returns the Target string if present or empty string if not.
func StringOrDefault(t rule.Target) string {
	if t == nil {
		return ""
	}

	if str, ok := t.(fmt.Stringer); ok {
		return str.String()
	}

	return ""
}

func runRule(ctx context.Context, p provider.Provider, rulesetID, rulesetVersion, ruleID string) error {
	res, err := p.RunRule(ctx, rulesetID, rulesetVersion, ruleID)
	if err != nil {
		return err
	}

	fmt.Printf("Rule: %s\n", res.RuleName)
	for _, cr := range res.CheckResults {
		fmt.Printf("- Status: %s %s Message: %s Target: %s\n", cr.Status, string(rule.GetStatusIcon(cr.Status)), cr.Message, StringOrDefault(cr.Target))
	}

	return nil
}

type runOptions struct {
	configFile     string
	all            bool
	provider       string
	rulesetID      string
	rulesetVersion string
	ruleID         string
}

type reportOptions struct {
	output string
}

func readConfig(filePath string) (*config.DikiConfig, error) {
	data, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return nil, err
	}

	c := &config.DikiConfig{}
	err = yaml.Unmarshal(data, c)

	if err != nil {
		return nil, err
	}

	return c, nil
}

func getProvidersFromConfig(c *config.DikiConfig, providerCreateFuncs map[string]provider.ProviderFromConfigFunc) (map[string]provider.Provider, error) {
	providers := map[string]provider.Provider{}
	for _, providerConfig := range c.Providers {
		if providerFunc, ok := providerCreateFuncs[providerConfig.ID]; ok {
			p, err := providerFunc(providerConfig)
			if err != nil {
				return nil, err
			}
			if _, ok := providers[p.ID()]; ok {
				return nil, fmt.Errorf("provider with id %s was already registered", p.ID())
			}
			providers[p.ID()] = p
		} else {
			return nil, fmt.Errorf("unknown provider identifier: %s", providerConfig.ID)
		}
	}

	return providers, nil
}
