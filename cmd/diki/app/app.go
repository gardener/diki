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
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/version"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/report"
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version details.",
		Long:  "Show version details.",
		RunE: func(_ *cobra.Command, _ []string) error {
			info := version.Get()
			jsonInfo, err := json.Marshal(info)
			if err != nil {
				return err
			}
			fmt.Print(string(jsonInfo))
			return nil
		},
	}

	var opts runOptions
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run some rulesets and rules.",
		Long:  `Run allows running rulesets and rules for the given provider(s).`,
		RunE: func(_ *cobra.Command, _ []string) error {
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
		RunE: func(_ *cobra.Command, args []string) error {
			return reportCmd(args, reportOpts)
		},
	}

	addReportFlags(reportCmd, &reportOpts)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(versionCmd)

	var diffOpts diffOptions
	diffCmd := &cobra.Command{
		Use:   "diff",
		Short: "Diff creates difference in 2 reports.",
		Long:  `Diff creates difference in 2 reports.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return diffCmd(args, diffOpts)
		},
	}

	addDiffFlags(diffCmd, &diffOpts)
	rootCmd.AddCommand(diffCmd)

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
	cmd.PersistentFlags().Var(cliflag.NewMapStringString(&opts.distinctBy), "distinct-by", "If set generates a merged report. The keys are the IDs for the providers which the merged report will include and the values are distinct metadata attributes to be used as IDs for the different reports.")
}

func addDiffFlags(cmd *cobra.Command, opts *diffOptions) {
	cmd.PersistentFlags().StringVar(&opts.oldReport, "old-report", "", "Old report path.")
	cmd.PersistentFlags().StringVar(&opts.newReport, "new-report", "", "New report path.")
}

func diffCmd(_ []string, opts diffOptions) error {
	if len(opts.oldReport) == 0 && len(opts.newReport) == 0 {
		return errors.New("diff command requires at least 1 report path")
	}

	var (
		oldReport *report.Report
		newReport *report.Report
	)

	if len(opts.oldReport) > 0 {
		oldReportfileData, err := os.ReadFile(filepath.Clean(opts.oldReport))
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", opts.oldReport, err)
		}

		if err := json.Unmarshal(oldReportfileData, oldReport); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
	}

	if len(opts.newReport) > 0 {
		newReportfileData, err := os.ReadFile(filepath.Clean(opts.newReport))
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", opts.newReport, err)
		}

		if err := json.Unmarshal(newReportfileData, newReport); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
	}

	diff, err := report.CreateDiff(*oldReport, *newReport)
	if err != nil {
		return fmt.Errorf("failed to create diff: %w", err)
	}

	jsonDiff, err := json.Marshal(diff)
	if err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	fmt.Print(string(jsonDiff))
	return nil
}

func reportCmd(args []string, opts reportOptions) error {
	if len(args) == 0 {
		return errors.New("report command requires a minimum of one filepath argument")
	}

	if len(args) > 1 && len(opts.distinctBy) == 0 {
		return errors.New("report command requires a single filepath argument when the distinct-by flag is not set")
	}

	if opts.output != "html" {
		return fmt.Errorf("unsuported output format: %s", opts.output)
	}

	reports := []*report.Report{}
	for _, arg := range args {
		fileData, err := os.ReadFile(filepath.Clean(arg))
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", arg, err)
		}

		// TODO: handle report types
		rep := &report.Report{}
		if err := json.Unmarshal(fileData, rep); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}

		reports = append(reports, rep)
	}

	htlmRenderer, err := report.NewHTMLRenderer()
	if err != nil {
		return fmt.Errorf("failed to initialize renderer: %w", err)
	}

	if len(opts.distinctBy) > 0 {
		mergedReport, err := report.MergeReport(reports, opts.distinctBy)
		if err != nil {
			return err
		}
		return htlmRenderer.Render(os.Stdout, mergedReport)
	}

	return htlmRenderer.Render(os.Stdout, reports[0])
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

func runRule(ctx context.Context, p provider.Provider, rulesetID, rulesetVersion, ruleID string) error {
	res, err := p.RunRule(ctx, rulesetID, rulesetVersion, ruleID)
	if err != nil {
		return err
	}

	j, err := json.Marshal(res)
	if err != nil {
		return err
	}

	fmt.Print(string(j))
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
	output     string
	distinctBy map[string]string
}

type diffOptions struct {
	oldReport string
	newReport string
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
