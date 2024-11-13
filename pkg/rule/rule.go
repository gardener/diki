// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"context"
	"maps"
	"slices"
)

// Rule defines what is considered a rule in the context of Diki.
type Rule interface {
	ID() string
	Name() string
	Run(ctx context.Context) (RuleResult, error)
}

// RuleResult contains a Rule identification and the results of a Rule run.
type RuleResult struct {
	RuleID, RuleName string
	Severity         SeverityLevel
	CheckResults     []CheckResult
}

// SeverityLevel defines the levels that can describe the importance of a Rule.
type SeverityLevel string

const (
	// SeverityLow indicates low severity.
	SeverityLow SeverityLevel = "Low"
	// SeverityMedium indicates medium severity.
	SeverityMedium SeverityLevel = "Medium"
	// SeverityHigh indicates high severity.
	SeverityHigh SeverityLevel = "High"
)

// Severity defines the importance of a rule.
type Severity interface {
	Severity() SeverityLevel
}

// Target is used to describe the things that were checked during ruleset runs.
type Target map[string]string

// NewTarget creates a new Target with the given key values.
// Panics if the number of arguments is an odd number.
func NewTarget(keyValuePairs ...string) Target {
	if len(keyValuePairs)%2 != 0 {
		panic("NewTarget: odd number of arguments")
	}
	t := Target{}

	for i := 0; i < len(keyValuePairs); i += 2 {
		t[keyValuePairs[i]] = keyValuePairs[i+1]
	}

	return t
}

// With creates a new Target with additional key values.
// It does not modify the original one.
// Panics if the number of arguments is an odd number.
func (t Target) With(keyValuePairs ...string) Target {
	if len(keyValuePairs)%2 != 0 {
		panic("With: odd number of arguments")
	}

	newTarget := maps.Clone(t)
	for i := 0; i < len(keyValuePairs); i += 2 {
		newTarget[keyValuePairs[i]] = keyValuePairs[i+1]
	}
	return newTarget
}

// CheckResult contains information about a Rule check. Returned from Rule runs.
type CheckResult struct {
	Status  Status
	Message string
	Target  Target
}

// Status of a CheckResult
type Status string

const (
	// Passed status indicates that a check is satisfied.
	Passed Status = "Passed"
	// Skipped status indicates that a rule is skipped with explanation.
	Skipped Status = "Skipped"
	// Accepted status indicates that a check violation is accepted and justified
	// based on additional configuration.
	Accepted Status = "Accepted"
	// Warning status indicates that there is ambiguity and the check was not performed with confidence.
	Warning Status = "Warning"
	// Failed status indicates that a check reported a violation.
	Failed Status = "Failed"
	// Errored status indicates that an unexpected error occured during check execution.
	Errored Status = "Errored"
	// NotImplemented status indicates that a rule/check is not implemented.
	NotImplemented Status = "Not Implemented"
)

// Statuses returns all supported statuses.
func Statuses() []Status {
	return []Status{Passed, Skipped, Accepted, Warning, Failed, Errored, NotImplemented}
}

var orderedStatuses = []Status{Passed, Skipped, Accepted, Warning, Failed, Errored, NotImplemented}

// Less is used to define the priority of the statuses.
// The ascending order is as follows
// Passed, Skipped, Accepted, Warning, Failed, Errored, Not Implemented
func (a Status) Less(b Status) bool {
	i := slices.IndexFunc(orderedStatuses, func(s Status) bool {
		return a == s
	})

	x := slices.IndexFunc(orderedStatuses, func(s Status) bool {
		return b == s
	})

	return i < x
}

// StatusIcon returns the icon of a given [Status] string.
func StatusIcon(status Status) rune {
	switch status {
	case Passed:
		return '🟢'
	case Failed, Errored:
		return '🔴'
	case Skipped, Accepted:
		return '🔵'
	case Warning, NotImplemented:
		return '🟠'
	default:
		return '⚪'
	}
}

// StatusDescription returns the description of a given [Status] string.
func StatusDescription(status Status) string {
	switch status {
	case Passed:
		return "Rule check has been fulfilled."
	case Failed:
		return "Rule check has been unfulfilled, can be considered a finding."
	case Errored:
		return "Rule check has errored during runtime. It cannot be determined whether the check is fulfilled or not."
	case Warning:
		return "Rule check has encountered an ambiguous condition or configuration preventing the ability to determine if the check is fulfilled or not."
	case Skipped:
		return "Rule check has been considered irrelevant for the specific scenario and will not be run."
	case Accepted:
		return "Rule check may or may not have been run, but it was decided by the user that the check is not a finding."
	case NotImplemented:
		return "Rule check has not been implemented yet."
	default:
		return "Unknown"
	}
}
