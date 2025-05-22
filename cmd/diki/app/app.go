// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	cliflag "k8s.io/component-base/cli/flag"
	"k8s.io/component-base/version"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/gardener/diki/cmd/internal/slogr"
	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/metadata"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/report"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

// NewDikiCommand creates a new command that is used to start Diki.
func NewDikiCommand(providerOptions map[string]provider.ProviderOption) *cobra.Command {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger := slog.New(handler)
	slog.SetDefault(logger)

	providerCreateFuncs := map[string]provider.ProviderFromConfigFunc{}
	for providerID, providerOption := range providerOptions {
		providerCreateFuncs[providerID] = providerOption.ProviderFromConfigFunc
	}

	metadataFuncs := map[string]provider.MetadataFunc{}
	for providerID, providerOption := range providerOptions {
		metadataFuncs[providerID] = providerOption.MetadataFunc
	}

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

	rootCmd.AddCommand(versionCmd)

	var opts runOptions
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run some rulesets and rules.",
		Long:  "Run allows running rulesets and rules for the given provider(s).",
		RunE: func(c *cobra.Command, _ []string) error {
			return runCmd(c.Context(), providerCreateFuncs, opts, logger)
		},
	}

	addRunFlags(runCmd, &opts)
	rootCmd.AddCommand(runCmd)

	var reportOpts reportOptions
	reportCmd := &cobra.Command{
		Use:   "report",
		Short: "Report is the root command for report operations.",
		Long:  "Report is the root command for report operations.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("report subcommand not selected")
		},
	}

	addReportFlags(reportCmd, &reportOpts)
	rootCmd.AddCommand(reportCmd)

	var generateOpts generateOptions
	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Report generate converts output files.",
		Long:  "Report generate converts output files.",
		RunE: func(_ *cobra.Command, args []string) error {
			return generateCmd(args, reportOpts, generateOpts, logger)
		},
	}

	addReportGenerateFlags(generateCmd, &generateOpts)
	reportCmd.AddCommand(generateCmd)

	var diffOpts diffOptions
	diffCmd := &cobra.Command{
		Use:   "diff",
		Short: "Report diff creates difference between two reports.",
		Long:  "Report diff creates difference between two reports.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return diffCmd(reportOpts, diffOpts)
		},
	}

	addReportDiffFlags(diffCmd, &diffOpts)
	reportCmd.AddCommand(diffCmd)

	var generateDiffOpts generateDiffOptions
	generateDiffCmd := &cobra.Command{
		Use:   "diff",
		Short: "Generate diff combines difference reports into an html report.",
		Long:  "Generate diff combines difference reports into an html report.",
		RunE: func(_ *cobra.Command, args []string) error {
			return generateDiffCmd(args, generateDiffOpts, reportOpts, logger)
		},
	}

	addReportGenerateDiffFlags(generateDiffCmd, &generateDiffOpts)
	generateCmd.AddCommand(generateDiffCmd)

	showCmd := &cobra.Command{
		Use:   "show",
		Short: "Show metadata information for different diki internals, i.e. providers.",
		Long:  "Show metadata information for different diki internals, i.e. providers.",
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("show subcommand not selected")
		},
	}

	rootCmd.AddCommand(showCmd)

	showProviderCmd := &cobra.Command{
		Use:   "provider",
		Short: "Show detailed information for providers.",
		Long:  "Show detailed information for providers.",
		RunE: func(_ *cobra.Command, args []string) error {
			return showProviderCmd(args, metadataFuncs)
		},
	}

	showCmd.AddCommand(showProviderCmd)

	return rootCmd
}

func addReportFlags(cmd *cobra.Command, opts *reportOptions) {
	cmd.PersistentFlags().StringVar(&opts.outputPath, "output", "", "Output path.")
}

func addRunFlags(cmd *cobra.Command, opts *runOptions) {
	cmd.PersistentFlags().StringVar(&opts.outputPath, "output", "", "If set diki writes a summary json report to the given file path.")
	cmd.PersistentFlags().StringVar(&opts.configFile, "config", "", "Configuration file for diki containing info about providers and rulesets.")
	cmd.PersistentFlags().BoolVar(&opts.all, "all", false, "If set to true diki will run all rulesets for all known providers.")
	cmd.PersistentFlags().StringVar(&opts.provider, "provider", "", "The provider that should be used to run checks.")
	cmd.PersistentFlags().StringVar(&opts.rulesetID, "ruleset-id", "", "The id of the ruleset that should be run. If provided --ruleset-version should also be set. If both flags are empty all rulesets for the provider will be run.")
	cmd.PersistentFlags().StringVar(&opts.rulesetVersion, "ruleset-version", "", "The version of the ruleset that should be run. If provided --ruleset-id should also be set. If both flags are empty all rulesets for the provider will be run.")
	cmd.PersistentFlags().StringVar(&opts.ruleID, "rule-id", "", "If set only the rule with the provided id will be run.")
}

func addReportGenerateFlags(cmd *cobra.Command, opts *generateOptions) {
	cmd.PersistentFlags().Var(cliflag.NewMapStringString(&opts.distinctBy), "distinct-by", "If set generates a merged report. The keys are the IDs for the providers which the merged report will include and the values are distinct metadata attributes to be used as IDs for the different reports.")
	cmd.PersistentFlags().StringVar(&opts.format, "format", "html", "Format for the output report. Format can be one of 'html' or 'json'.")
	cmd.PersistentFlags().StringVar(&opts.minStatus, "min-status", "Passed", "If set specifies the minimal status that will be included in the generated report. Ordered from lowest to highest priority, Status can be one of 'Passed', 'Skipped', 'Accepted', 'Warning', 'Failed', 'Errored' or 'NotImplemented'")
}

func addReportDiffFlags(cmd *cobra.Command, opts *diffOptions) {
	cmd.PersistentFlags().StringVar(&opts.oldReport, "old", "", "Old report path.")
	cmd.PersistentFlags().StringVar(&opts.newReport, "new", "", "New report path.")
	cmd.PersistentFlags().StringVar(&opts.title, "title", "", "The title of a difference report.")
}

func addReportGenerateDiffFlags(cmd *cobra.Command, opts *generateDiffOptions) {
	cmd.PersistentFlags().Var(cliflag.NewMapStringString(&opts.identityAttributes), "identity-attributes", "The keys are the IDs of the providers that will be present in the generated difference report and the values are metadata attributes to be used as identifiers.")
}

func showProviderCmd(args []string, metadataFuncs map[string]provider.MetadataFunc) error {
	if len(args) > 1 {
		return errors.New("command 'show provider' accepts at most one provider")
	}

	if len(args) == 0 {
		var providersMetadata []metadata.Provider

		for providerID := range metadataFuncs {
			providersMetadata = append(providersMetadata, metadata.Provider{ID: providerID, Name: metadataFuncs[providerID]().Name})
		}

		if bytes, err := json.Marshal(providersMetadata); err != nil {
			return err
		} else {
			fmt.Println(string(bytes))
		}
		return nil
	}

	metadataFunc, ok := metadataFuncs[args[0]]
	if !ok {
		return fmt.Errorf("unknown provider: %s", args[0])
	}

	if bytes, err := json.Marshal(metadataFunc()); err != nil {
		return err
	} else {
		fmt.Println(string(bytes))
	}
	return nil
}

func generateDiffCmd(args []string, generateDiffOpts generateDiffOptions, rootOpts reportOptions, logger *slog.Logger) error {
	if len(args) == 0 {
		return errors.New("generate diff command requires a minimum of one filepath argument")
	}
	if len(generateDiffOpts.identityAttributes) == 0 {
		return errors.New("--identity-attributes is not set but required")
	}

	var differences []*report.DifferenceReport
	for _, arg := range args {
		fileData, err := os.ReadFile(filepath.Clean(arg))
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", arg, err)
		}

		diff := &report.DifferenceReport{}
		if err := json.Unmarshal(fileData, diff); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}

		differences = append(differences, diff)
	}

	var writer io.Writer = os.Stdout
	if len(rootOpts.outputPath) > 0 {
		file, err := os.OpenFile(rootOpts.outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer func() {
			if err := file.Close(); err != nil {
				logger.Error(err.Error())
			}
		}()
		writer = file
	}

	htmlRenderer, err := report.NewHTMLRenderer()
	if err != nil {
		return fmt.Errorf("failed to initialize renderer: %w", err)
	}

	return htmlRenderer.Render(writer, &report.DifferenceReportsWrapper{
		DifferenceReports:  differences,
		IdentityAttributes: generateDiffOpts.identityAttributes,
	})
}

func diffCmd(rootOpts reportOptions, opts diffOptions) error {
	if len(opts.oldReport) == 0 && len(opts.newReport) == 0 {
		return errors.New("diff command requires at least 1 report path")
	}

	var (
		oldReport report.Report
		newReport report.Report
	)

	if len(opts.oldReport) > 0 {
		oldReportfileData, err := os.ReadFile(filepath.Clean(opts.oldReport))
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", opts.oldReport, err)
		}

		if err := json.Unmarshal(oldReportfileData, &oldReport); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
	}

	if len(opts.newReport) > 0 {
		newReportfileData, err := os.ReadFile(filepath.Clean(opts.newReport))
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", opts.newReport, err)
		}

		if err := json.Unmarshal(newReportfileData, &newReport); err != nil {
			return fmt.Errorf("failed to unmarshal data: %w", err)
		}
	}

	diff, err := report.CreateDifference(oldReport, newReport, opts.title)
	if err != nil {
		return fmt.Errorf("failed to create diff: %w", err)
	}

	jsonDiff, err := json.Marshal(diff)
	if err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	if len(rootOpts.outputPath) > 0 {
		return os.WriteFile(rootOpts.outputPath, jsonDiff, 0600)
	}

	fmt.Print(string(jsonDiff))
	return nil
}

func generateCmd(args []string, rootOpts reportOptions, opts generateOptions, logger *slog.Logger) error {
	if len(args) == 0 {
		return errors.New("generate command requires a minimum of one filepath argument")
	}

	if len(args) > 1 && len(opts.distinctBy) == 0 {
		return errors.New("generate command requires a single filepath argument when the distinct-by flag is not set")
	}

	minStatus := rule.Passed
	if len(opts.minStatus) != 0 {
		minStatus = rule.Status(opts.minStatus)
		if !slices.Contains(rule.Statuses(), minStatus) {
			return fmt.Errorf("not defined status: %s", minStatus)
		}
	}

	var reports []*report.Report
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

		rep.SetMinStatus(minStatus)
		reports = append(reports, rep)
	}

	var writer io.Writer = os.Stdout
	if len(rootOpts.outputPath) > 0 {
		file, err := os.OpenFile(rootOpts.outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer func() {
			if err := file.Close(); err != nil {
				logger.Error(err.Error())
			}
		}()
		writer = file
	}

	var outputReport any
	outputReport = reports[0]

	if len(opts.distinctBy) > 0 {
		mergedReport, err := report.MergeReport(reports, opts.distinctBy)
		if err != nil {
			return err
		}

		outputReport = mergedReport
	}

	switch opts.format {
	case "html":
		htmlRenderer, err := report.NewHTMLRenderer()
		if err != nil {
			return fmt.Errorf("failed to initialize renderer: %w", err)
		}

		return htmlRenderer.Render(writer, outputReport)
	case "json":
		data, err := json.Marshal(outputReport)
		if err != nil {
			return err
		}

		_, err = writer.Write(data)
		return err
	default:
		return fmt.Errorf("not supported output format %s. Choose one of 'html' or 'json'", opts.format)
	}
}

func runCmd(ctx context.Context, providerCreateFuncs map[string]provider.ProviderFromConfigFunc, opts runOptions, logger *slog.Logger) error {
	// Set logger for controller-runtime clients
	logr := slogr.NewLogr(logger)
	logf.SetLogger(logr)

	dikiConfig, err := readConfig(opts.configFile)
	if err != nil {
		return err
	}

	outputPath := opts.outputPath
	if len(outputPath) == 0 && dikiConfig.Output != nil && len(dikiConfig.Output.Path) > 0 {
		outputPath = dikiConfig.Output.Path
	}

	providers, err := getProvidersFromConfig(dikiConfig, providerCreateFuncs)
	if err != nil {
		return err
	}

	if opts.all {
		var providerResults []provider.ProviderResult
		for _, p := range providers {
			res, err := p.RunAll(ctx)
			if err != nil {
				return err
			}
			providerResults = append(providerResults, res)
		}

		if len(outputPath) > 0 {
			var reportOpts []report.ReportOption
			if dikiConfig.Output != nil && len(dikiConfig.Output.MinStatus) > 0 {
				reportOpts = append(reportOpts, report.MinStatus(dikiConfig.Output.MinStatus))
			}
			if len(dikiConfig.Metadata) > 0 {
				reportOpts = append(reportOpts, report.Metadata(dikiConfig.Metadata))
			}
			rep := report.FromProviderResults(providerResults, reportOpts...)
			return rep.WriteToFile(outputPath)
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

		if len(outputPath) > 0 {
			var reportOpts []report.ReportOption
			if dikiConfig.Output != nil && len(dikiConfig.Output.MinStatus) > 0 {
				reportOpts = append(reportOpts, report.MinStatus(dikiConfig.Output.MinStatus))
			}
			if len(dikiConfig.Metadata) > 0 {
				reportOpts = append(reportOpts, report.Metadata(dikiConfig.Metadata))
			}
			rep := report.FromProviderResults(providerResults, reportOpts...)
			return rep.WriteToFile(outputPath)
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
		providerResults := []provider.ProviderResult{{ProviderID: p.ID(), ProviderName: p.Name(), Metadata: p.Metadata(), RulesetResults: []ruleset.RulesetResult{res}}}

		if len(outputPath) > 0 {
			var reportOpts []report.ReportOption
			if dikiConfig.Output != nil && len(dikiConfig.Output.MinStatus) > 0 {
				reportOpts = append(reportOpts, report.MinStatus(dikiConfig.Output.MinStatus))
			}
			if len(dikiConfig.Metadata) > 0 {
				reportOpts = append(reportOpts, report.Metadata(dikiConfig.Metadata))
			}
			rep := report.FromProviderResults(providerResults, reportOpts...)
			return rep.WriteToFile(outputPath)
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

type reportOptions struct {
	outputPath string
}

type runOptions struct {
	outputPath     string
	configFile     string
	all            bool
	provider       string
	rulesetID      string
	rulesetVersion string
	ruleID         string
}

type generateOptions struct {
	distinctBy map[string]string
	format     string
	minStatus  string
}

type generateDiffOptions struct {
	identityAttributes map[string]string
}

type diffOptions struct {
	oldReport string
	newReport string
	title     string
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
