// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package gardenlinux

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
	disaoption "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

const (
	// RulesetID is a constant containing the id of the Gardenlinux Ruleset.
	RulesetID = "gardenlinux"
	// RulesetName is a constant containing the user-friendly name of the Gardenlinux ruleset.
	RulesetName = "Gardenlinux Testing Framework"
)

var (
	_ ruleset.Ruleset = &Ruleset{}
	// SupportedVersions is a list of available versions for the Gardenlinux Ruleset.
	// Versions are sorted from newest to oldest.
	// TODO(georgibaltiev): introduce support for actual gardenlinux versions and remove dummy values
	SupportedVersions = []string{"v0.1.0"}
)

// Ruleset implements the Gardenlinux Testing Framework ruleset.
type Ruleset struct {
	version    string
	Config     *rest.Config
	numWorkers int
	args       Args
	instanceID string
	logger     *slog.Logger
}

// Args are Ruleset specific arguments.
type Args struct {
	NodeGroupByLabels []string `json:"nodeGroupByLabels" yaml:"nodeGroupByLabels"`
}

// New creates a new Ruleset.
func New(options ...CreateOption) (*Ruleset, error) {
	r := &Ruleset{
		numWorkers: 5,
		instanceID: uuid.New().String(),
	}

	for _, o := range options {
		o(r)
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
	return ruleset, nil
}

// ValidateRulesetConfig validates a [config.RulesetConfig].
func ValidateRulesetConfig(rulesetConfig config.RulesetConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	if !slices.Contains(SupportedVersions, rulesetConfig.Version) {
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("version"), rulesetConfig.Version, SupportedVersions))
	}

	rulesetArgsByte, err := json.Marshal(rulesetConfig.Args)
	if err != nil {
		return append(allErrs, field.Invalid(fldPath.Child("args"), rulesetConfig.Args, err.Error()))
	}

	var rulesetArgs Args
	if err := json.Unmarshal(rulesetArgsByte, &rulesetArgs); err != nil {
		return append(allErrs, field.Invalid(fldPath.Child("args"), rulesetConfig.Args, err.Error()))
	}

	allErrs = append(allErrs, disaoption.ValidateLabelNames(rulesetArgs.NodeGroupByLabels, fldPath.Child("args", "nodeGroupByLabels"))...)

	if len(rulesetConfig.RuleOptions) > 0 {
		allErrs = append(allErrs, field.Forbidden(fldPath.Child("ruleOptions"), "the gardenlinux ruleset does not accept per-rule options"))
	}

	return allErrs
}

// Run executes the gardenlinux test Pods and collects the test results.
// TODO(georgibaltiev): add implementation for the integration of the Gardenlinux ruleset here.
func (r *Ruleset) Run(_ context.Context) (ruleset.RulesetResult, error) {
	r.Logger().Warn("the gardenlinux ruleset is not yet supported")
	return ruleset.RulesetResult{}, nil
}

// RunRule executes specific Rule of a known Ruleset.
// The function is not supported for this ruleset, since the implementation of the framework is external
func (r *Ruleset) RunRule(_ context.Context, _ string) (rule.RuleResult, error) {
	return rule.RuleResult{}, fmt.Errorf("the gardenlinux ruleset does not support running rules individually")
}

// Logger returns the Ruleset's logger.
// If not set, set it to slog.Default().With("ruleset", r.ID(), "version", r.Version() then return it.
func (r *Ruleset) Logger() *slog.Logger {
	if r.logger == nil {
		r.logger = slog.Default().With("ruleset", r.ID(), "version", r.Version())
	}
	return r.logger
}
