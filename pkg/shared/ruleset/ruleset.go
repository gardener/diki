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
)

// Logger is a minimalistic logger interface.
type Logger interface {
	Info(string, ...any)
	Error(string, ...any)
}

// Run is a sample implementation for a [ruleset.Ruleset].
func Run(
	ctx context.Context,
	r ruleset.Ruleset,
	rules map[string]rule.Rule,
	numWorkers int,
	log Logger,
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
	log.Info(fmt.Sprintf("ruleset will run %d rules with %d concurrent workers", len(rules), workers))
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			for rule := range rulesCh {
				log.Info(fmt.Sprintf("starting rule %s run", rule.ID()))
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
		finishMsg := fmt.Sprintf("finished rule %s run (%d remaining)", run.result.RuleID, remaining)
		if run.err != nil {
			log.Error(finishMsg, "error", run.err)
			err = errors.Join(err, fmt.Errorf("rule with id %s errored: %w", run.result.RuleID, run.err))
		} else {
			log.Info(finishMsg)
			result.RuleResults = append(result.RuleResults, run.result)
		}
	}
	// TODO: maybe return both result and err
	if err != nil {
		return ruleset.RulesetResult{}, err
	}
	return result, nil
}
