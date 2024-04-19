// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package ruleset

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
	"github.com/gardener/diki/pkg/shared/provider"
)

// Run is a sample implementation for a [ruleset.Ruleset].
func Run(
	ctx context.Context,
	r ruleset.Ruleset,
	rules map[string]rule.Rule,
	numWorkers int,
	log provider.Logger,
) (ruleset.RulesetResult, error) {
	if len(rules) == 0 {
		return ruleset.RulesetResult{}, fmt.Errorf("no rules are registered in the ruleset")
	}

	workers := 1
	if numWorkers > 0 {
		workers = numWorkers
	}

	result := ruleset.RulesetResult{
		RulesetName:    r.Name(),
		RulesetID:      r.ID(),
		RulesetVersion: r.Version(),
		RuleResults:    make([]rule.RuleResult, 0, len(rules)),
	}

	type run struct {
		result rule.RuleResult
		err    error
	}

	rulesCh := make(chan rule.Rule)
	resultCh := make(chan run)
	wg := sync.WaitGroup{}
	log.Info("starting ruleset run", "rules", len(rules), "concurrent workers", workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			for rule := range rulesCh {
				log.Info("starting rule run", "rule_id", rule.ID())
				res, err := rule.Run(ctx)
				res.RuleID = rule.ID()
				res.RuleName = rule.Name()
				resultCh <- run{result: res, err: err}
			}
			wg.Done()
		}()
	}

	go func() {
		for _, r := range rules {
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
		remaining := len(rules) - resultCount
		finishMsg := "finished rule run"
		if run.err != nil {
			log.Error(finishMsg, "rule_id", run.result.RuleID, "remaining", remaining, "error", run.err)
			err = errors.Join(err, fmt.Errorf("rule with id %s errored: %w", run.result.RuleID, run.err))
		} else {
			log.Info(finishMsg, "rule_id", run.result.RuleID, "remaining", remaining)
			result.RuleResults = append(result.RuleResults, run.result)
		}
	}
	// TODO: maybe return both result and err
	if err != nil {
		return ruleset.RulesetResult{}, err
	}
	return result, nil
}
