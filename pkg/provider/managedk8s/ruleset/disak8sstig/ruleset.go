// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"

	"github.com/gardener/diki/pkg/config"
	internalconfig "github.com/gardener/diki/pkg/internal/config"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
	sharedruleset "github.com/gardener/diki/pkg/shared/ruleset"
)

const (
	// RulesetID is a constant containing the id of the DISA Kubernetes STIG Ruleset.
	RulesetID = "disa-kubernetes-stig"
	// RulesetName is a constant containing the user-friendly name of the DISA Kubernetes STIG ruleset.
	RulesetName = "DISA Kubernetes Security Technical Implementation Guide"
)

var (
	_ ruleset.Ruleset = &Ruleset{}
	// SupportedVersions is a list of available versions for the DISA Kubernetes STIG Ruleset.
	// Versions are sorted from newest to oldest.
	SupportedVersions = []string{"v2r5", "v2r4"}
)

// Ruleset implements DISA Kubernetes STIG.
type Ruleset struct {
	version                string
	rules                  map[string]rule.Rule
	AdditionalOpsPodLabels map[string]string
	Config                 *rest.Config
	numWorkers             int
	args                   Args
	instanceID             string
	logger                 *slog.Logger
}

// Args are Ruleset specific arguments.
type Args struct {
	MaxRetries *int `json:"maxRetries" yaml:"maxRetries"`
}

// New creates a new Ruleset.
func New(options ...CreateOption) (*Ruleset, error) {
	r := &Ruleset{
		rules:      map[string]rule.Rule{},
		numWorkers: 5,
		args: Args{
			MaxRetries: ptr.To(1),
		},
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
func FromGenericConfig(rulesetConfig config.RulesetConfig, additionalOpsPodLabels map[string]string, managedConfig *rest.Config, fldPath *field.Path) (*Ruleset, error) {
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
		WithAdditionalOpsPodLabels(additionalOpsPodLabels),
		WithConfig(managedConfig),
		WithArgs(rulesetArgs),
	)
	if err != nil {
		return nil, err
	}

	var (
		ruleOptions        = make(map[string]config.RuleOptionsConfig)
		indexedRuleOptions = make(map[string]internalconfig.IndexedRuleOptionsConfig)
	)

	for index, opt := range rulesetConfig.RuleOptions {
		if _, ok := ruleOptions[opt.RuleID]; ok {
			return nil, fmt.Errorf("rule option for rule id: %s is already registered", opt.RuleID)
		}

		ruleOptions[opt.RuleID] = opt
		indexedRuleOptions[opt.RuleID] = internalconfig.IndexedRuleOptionsConfig{Index: index, RuleOptionsConfig: opt}
	}

	switch rulesetConfig.Version {
	case "v2r4":
		if err := ruleset.validateV2R4RuleOptions(indexedRuleOptions, fldPath.Child("ruleOptions")); err != nil {
			return nil, err
		}
		if err := ruleset.registerV2R4Rules(ruleOptions); err != nil {
			return nil, err
		}
	case "v2r5":
		if err := ruleset.validateV2R5RuleOptions(indexedRuleOptions, fldPath.Child("ruleOptions")); err != nil {
			return nil, err
		}
		if err := ruleset.registerV2R5Rules(ruleOptions); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown ruleset %s version: %s - use 'diki show provider managedk8s' to see the provider's supported rulesets", rulesetConfig.ID, rulesetConfig.Version)
	}

	return ruleset, nil
}

// RunRule executes specific known Rule of the Ruleset.
func (r *Ruleset) RunRule(ctx context.Context, id string) (rule.RuleResult, error) {
	rr, ok := r.rules[id]
	if !ok {
		return rule.RuleResult{}, fmt.Errorf("rule with id %s is not registered in the ruleset", id)
	}

	return rr.Run(ctx)
}

// Run executes all known Rules of the Ruleset.
func (r *Ruleset) Run(ctx context.Context) (ruleset.RulesetResult, error) {
	return sharedruleset.Run(ctx, r, r.rules, r.numWorkers, r.Logger())
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
// If not set it set it to slog.Default().With("ruleset", r.ID(), "version", r.Version() then return it.
func (r *Ruleset) Logger() *slog.Logger {
	if r.logger == nil {
		r.logger = slog.Default().With("ruleset", r.ID(), "version", r.Version())
	}
	return r.logger
}
