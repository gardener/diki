// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package securityhardenedshoot

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
	sharedruleset "github.com/gardener/diki/pkg/shared/ruleset"
)

const (
	// RulesetID is a constant containing the id of a Security Hardened Shoot Cluster Ruleset
	RulesetID = "security-hardened-shoot-cluster"
)

var _ ruleset.Ruleset = &Ruleset{}

// Ruleset implements Security Hardened Shoot Cluster.
type Ruleset struct {
	version    string
	rules      map[string]rule.Rule
	Config     *rest.Config
	numWorkers int
	args       Args
	logger     *slog.Logger
}

// Args are Ruleset specific arguments.
type Args struct {
	ShootName        string `json:"shootName" yaml:"shootName"`
	ProjectNamespace string `json:"projectNamespace" yaml:"projectNamespace"`
}

// New creates a new Ruleset.
func New(options ...CreateOption) (*Ruleset, error) {
	r := &Ruleset{
		rules:      map[string]rule.Rule{},
		numWorkers: 5,
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
	return "Security Hardened Shoot Cluster"
}

// Version returns the version of the Ruleset.
func (r *Ruleset) Version() string {
	return r.version
}

// FromGenericConfig creates a Ruleset from a RulesetConfig
func FromGenericConfig(rulesetConfig config.RulesetConfig, managedConfig *rest.Config) (*Ruleset, error) {
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

	ruleOptions := map[string]config.RuleOptionsConfig{}
	for _, opt := range rulesetConfig.RuleOptions {
		if _, ok := ruleOptions[opt.RuleID]; ok {
			return nil, fmt.Errorf("rule option for rule id: %s is already registered", opt.RuleID)
		}

		ruleOptions[opt.RuleID] = opt
	}

	switch rulesetConfig.Version {
	case "v0.1.0":
		if err := ruleset.registerV01Rules(ruleOptions); err != nil {
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
