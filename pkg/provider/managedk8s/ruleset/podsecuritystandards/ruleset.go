// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package podsecuritystandards

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
	sharedruleset "github.com/gardener/diki/pkg/shared/ruleset"
)

const (
	// RulesetID is a constant containing the id of the Pod Security Standards Ruleset.
	RulesetID = "pod-security-standards"
	// RulesetName is a constant containing the user-friendly name of the Pod Security Standards Ruleset.
	RulesetName = "Pod Security Standards"
)

var (
	_ ruleset.Ruleset = &Ruleset{}
	// SupportedVersions is a list of available versions for the Pod Security Standards Ruleset.
	// Versions are sorted from newest to oldest.
	SupportedVersions = []string{"v0.1.0"}
)

// Ruleset implements Pod Security Standards Ruleset.
type Ruleset struct {
	version    string
	rules      map[string]rule.Rule
	Config     *rest.Config
	numWorkers int
	logger     *slog.Logger
	args       Args
}

// Args are Ruleset specific arguments.
// TBD if args and what args
type Args struct {
	TBD *string `json:"TBD" yaml:"TBD"`
}

// New creates a new Ruleset.
func New(options ...CreateOption) (*Ruleset, error) {
	r := &Ruleset{
		rules: map[string]rule.Rule{},
	}

	for _, opt := range options {
		opt(r)
	}

	return r, nil
}

// ID returns the id of the Ruleset.
func (r *Ruleset) ID() string {
	return RulesetID
}

// Name returns the name of the Ruleset.
func (r *Ruleset) Name() string {
	return RulesetName
}

// Version returns the version of the Ruleset.
func (r *Ruleset) Version() string {
	return r.version
}

// FromGenericConfig creates a Ruleset from a RulesetConfig
func FromGenericConfig(rulesetConfig config.RulesetConfig, managedConfig *rest.Config, fldPath *field.Path) (*Ruleset, error) {
	if errs := ValidateRulesetConfig(rulesetConfig, fldPath); len(errs) > 0 {
		return nil, errs.ToAggregate()
	}

	rulesetArgsByte, err := json.Marshal(rulesetConfig.Args)
	if err != nil {
		return nil, err
	}

	var rulesetArgs Args
	if err := json.Unmarshal(rulesetArgsByte, &rulesetArgs); err != nil {
		return nil, err
	}

	ruleset, err := New(
		WithVersion(rulesetConfig.Version),
		WithConfig(managedConfig),
		WithArgs(rulesetArgs),
	)
	if err != nil {
		return nil, err
	}

	ruleOptions := make(map[string]config.RuleOptionsConfig)
	for _, opt := range rulesetConfig.RuleOptions {
		ruleOptions[opt.RuleID] = opt
	}

	if err := ruleset.registerRules(ruleOptions); err != nil {
		return nil, err
	}

	return ruleset, nil
}

// ValidateRulesetConfig validates a [config.RulesetConfig].
func ValidateRulesetConfig(rulesetConfig config.RulesetConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	indexedRuleOptions, err := sharedruleset.IndexRuleOptions(rulesetConfig.RuleOptions)
	if err != nil {
		return append(allErrs, field.Invalid(fldPath.Child("ruleOptions"), rulesetConfig.RuleOptions, err.Error()))
	}

	r := &Ruleset{}
	switch rulesetConfig.Version {
	case "v0.1.0":
		allErrs = append(allErrs, r.validateV01RuleOptions(indexedRuleOptions, fldPath.Child("ruleOptions"))...)
	default:
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("version"), rulesetConfig.Version, SupportedVersions))
	}

	return allErrs
}

// Run executes all known Rules of the Ruleset.
func (r *Ruleset) Run(ctx context.Context) (ruleset.RulesetResult, error) {
	return sharedruleset.Run(ctx, r, r.rules, r.numWorkers, r.Logger())
}

// RunRule executes specific known Rule of the Ruleset.
func (r *Ruleset) RunRule(ctx context.Context, id string) (rule.RuleResult, error) {
	rr, ok := r.rules[id]
	if !ok {
		return rule.RuleResult{}, fmt.Errorf("rule with id %s is not registered in the ruleset", id)
	}

	return rr.Run(ctx)
}

// AddRules adds Rules to the Ruleset.
func (r *Ruleset) AddRules(rules ...rule.Rule) error {
	for _, rr := range rules {
		if _, ok := r.rules[rr.ID()]; ok {
			return fmt.Errorf("rule with id %s already exists", rr.ID())
		}
		r.rules[rr.ID()] = rr
	}
	return nil
}

// Logger returns the Ruleset's logger.
// Defaults to slog.Default().With("ruleset", r.ID(), "version", r.Version() if unset
func (r *Ruleset) Logger() *slog.Logger {
	if r.logger == nil {
		r.logger = slog.Default().With("ruleset", r.ID(), "version", r.Version())
	}

	return r.logger
}

func (r *Ruleset) registerRules(ruleOptions map[string]config.RuleOptionsConfig) error {
	switch r.version {
	case "v0.1.0":
		return r.registerV01Rules(ruleOptions)
	default:
		return sharedruleset.UnknownVersionError(r.ID(), r.Version(), "managedk8s")
	}
}
