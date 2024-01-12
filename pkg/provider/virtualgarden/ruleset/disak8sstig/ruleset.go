// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
	sharedruleset "github.com/gardener/diki/pkg/shared/ruleset"
)

const (
	// RulesetID is a constant containing the id of a DISA Kubernetes STIG Ruleset
	RulesetID = "disa-kubernetes-stig"
)

var _ ruleset.Ruleset = &Ruleset{}

// Ruleset implements DISA Kubernetes STIG.
type Ruleset struct {
	version                     string
	rules                       map[string]rule.Rule
	GardenConfig, RuntimeConfig *rest.Config
	numWorkers                  int
	instanceID                  string
	logger                      *slog.Logger
}

// New creates a new Ruleset.
func New(options ...CreateOption) (*Ruleset, error) {
	r := &Ruleset{
		rules:      map[string]rule.Rule{},
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
	return "DISA Kubernetes Security Technical Implementation Guide"
}

// Version returns the version of the Ruleset.
func (r *Ruleset) Version() string {
	return r.version
}

// FromGenericConfig creates a Ruleset from a RulesetConfig
func FromGenericConfig(rulesetConfig config.RulesetConfig, gardenConfig, runtimeConfig *rest.Config) (*Ruleset, error) {
	ruleset, err := New(
		WithVersion(rulesetConfig.Version),
		WithGardenConfig(gardenConfig),
		WithRuntimeConfig(runtimeConfig),
	)
	if err != nil {
		return nil, err
	}

	ruleOptions := map[string]config.RuleOptionsConfig{}
	for _, opt := range rulesetConfig.RuleOptions {
		if _, ok := ruleOptions[opt.RuleID]; ok {
			return nil, fmt.Errorf("rule option for rule id: %s is already registered", opt.RuleID)
		}

		ruleOptions[opt.RuleID] = opt
	}

	switch rulesetConfig.Version {
	case "v1r11":
		if err := ruleset.registerV1R11Rules(ruleOptions); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown ruleset %s version: %s", rulesetConfig.ID, rulesetConfig.Version)
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
