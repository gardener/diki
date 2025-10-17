// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	"github.com/gardener/diki/pkg/metadata"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

// Provider defines a Diki provider.
type Provider interface {
	ID() string
	Name() string
	Metadata() map[string]string
	RunAll(ctx context.Context) (ProviderResult, error)
	RunRuleset(ctx context.Context, rulesetID, rulesetVersion string) (ruleset.RulesetResult, error)
	RunRule(ctx context.Context, rulesetID, rulesetVersion, ruleID string) (rule.RuleResult, error)
}

// ProviderResult is the result of a provider run.
type ProviderResult struct {
	ProviderID     string
	ProviderName   string
	Metadata       map[string]string
	RulesetResults []ruleset.RulesetResult
}

// ProviderFromConfigFunc constructs a Provider from ProviderConfig.
type ProviderFromConfigFunc func(conf config.ProviderConfig, fldPath *field.Path) (Provider, error)

// MetadataFunc constructs a detailed Provider metadata object.
type MetadataFunc func() metadata.ProviderDetailed

// DefaultDikiConfigFunc constructs a default [config.DikiConfig] for a specific provider.
type DefaultDikiConfigFunc func() config.DikiConfig

// ProviderOption constructs a pair of a configuration and metadata function for a specific provider.
type ProviderOption struct {
	ProviderFromConfigFunc
	MetadataFunc
	DefaultDikiConfigFunc
}
