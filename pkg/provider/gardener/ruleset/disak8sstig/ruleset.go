// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package disak8sstig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/google/uuid"
	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

const (
	// RulesetID is a constant containing the id of a DISA Kubernetes STIG Ruleset
	RulesetID = "disa-kubernetes-stig"
)

var _ ruleset.Ruleset = &Ruleset{}

// Ruleset implements DISA Kubernetes STIG.
type Ruleset struct {
	version                 string
	rules                   map[string]rule.Rule
	ShootConfig, SeedConfig *rest.Config
	shootNamespace          string
	numWorkers              int
	instanceID              string
	logger                  *slog.Logger
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

	// TODO: add validation
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
func FromGenericConfig(rulesetConfig config.RulesetConfig, shootConfig, seedConfig *rest.Config, shootNamespace string) (*Ruleset, error) {
	// TODO: add all known rules and validate
	ruleset, err := New(
		WithVersion(rulesetConfig.Version),
		WithShootConfig(shootConfig),
		WithSeedConfig(seedConfig),
		WithShootNamespace(shootNamespace),
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
	case "v1r8":
		if err := ruleset.registerV1R8Rules(ruleOptions); err != nil {
			return nil, err
		}
	case "v1r10":
		if err := ruleset.registerV1R10Rules(ruleOptions); err != nil {
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
	if len(r.rules) == 0 {
		return ruleset.RulesetResult{}, fmt.Errorf("no rules are registered in the ruleset")
	}

	result := ruleset.RulesetResult{
		RulesetName:    r.Name(),
		RulesetID:      r.ID(),
		RulesetVersion: r.Version(),
		RuleResults:    make([]rule.RuleResult, 0, len(r.rules)),
	}

	type run struct {
		result rule.RuleResult
		err    error
	}

	rulesCh := make(chan rule.Rule)
	resultCh := make(chan run)
	wg := sync.WaitGroup{}
	r.Logger().Info(fmt.Sprintf("ruleset will run %d rules with %d concurrent workers", len(r.rules), r.numWorkers))
	for i := 0; i < r.numWorkers; i++ {
		wg.Add(1)
		go func() {
			for rule := range rulesCh {
				r.Logger().Info(fmt.Sprintf("starting rule %s run", rule.ID()))
				res, err := rule.Run(ctx)
				res.RuleID = rule.ID()
				res.RuleName = rule.Name()
				resultCh <- run{result: res, err: err}
			}
			wg.Done()
		}()
	}

	go func() {
		for _, r := range r.rules {
			rulesCh <- r
		}
		close(rulesCh)
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	var err error
	resultCount := 0
	for run := range resultCh {
		resultCount++
		remaining := len(r.rules) - resultCount
		finishMsg := fmt.Sprintf("finished rule %s run (%d remaining)", run.result.RuleID, remaining)
		if run.err != nil {
			r.Logger().Error(finishMsg, "error", run.err)
			err = errors.Join(err, fmt.Errorf("rule with id %s errored: %w", run.result.RuleID, run.err))
		} else {
			r.Logger().Info(finishMsg)
			result.RuleResults = append(result.RuleResults, run.result)
		}
	}
	// TODO: maybe return both result and err
	if err != nil {
		return ruleset.RulesetResult{}, err
	}
	return result, nil
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
