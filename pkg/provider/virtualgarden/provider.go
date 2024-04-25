// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package virtualgarden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
	sharedprovider "github.com/gardener/diki/pkg/shared/provider"
)

// Provider is a Garden Cluster Provider that can be used to implement rules
// against a virtual garden cluster and its controlplane (residing in a runtime cluster).
type Provider struct {
	id, name      string
	OpsPodLabels  map[string]string
	RuntimeConfig *rest.Config
	rulesets      map[string]ruleset.Ruleset
	metadata      map[string]string
	logger        *slog.Logger
}

type providerArgs struct {
	OpsPodLabels          map[string]string `json:"opsPodLabels" yaml:"opsPodLabels"`
	RuntimeKubeconfigPath string            `json:"runtimeKubeconfigPath" yaml:"runtimeKubeconfigPath"`
}

var _ provider.Provider = &Provider{}

// New creates a new Provider.
func New(options ...CreateOption) (*Provider, error) {
	p := &Provider{
		rulesets: make(map[string]ruleset.Ruleset),
	}
	for _, o := range options {
		o(p)
	}

	var err error
	if p.RuntimeConfig == nil {
		err = errors.Join(err, errors.New("runtime cluster config is nil"))
	}

	if err != nil {
		return nil, err
	}

	return p, nil
}

// RunAll executes all Rulesets registered with the Provider.
func (p *Provider) RunAll(ctx context.Context) (provider.ProviderResult, error) {
	return sharedprovider.RunAll(ctx, p, p.rulesets, p.Logger())
}

func rulesetKey(rulesetID, rulesetVersion string) string {
	return rulesetID + "--" + rulesetVersion
}

// RunRuleset executes all Rules of a known Ruleset.
func (p *Provider) RunRuleset(ctx context.Context, rulesetID, rulesetVersion string) (ruleset.RulesetResult, error) {
	rs, ok := p.rulesets[rulesetKey(rulesetID, rulesetVersion)]
	if !ok {
		return ruleset.RulesetResult{}, fmt.Errorf("ruleset with id %s and version %s does not exist", rulesetID, rulesetVersion)
	}
	return rs.Run(ctx)
}

// RunRule executes specific Rule of a known Ruleset.
func (p *Provider) RunRule(ctx context.Context, rulesetID, rulesetVersion, ruleID string) (rule.RuleResult, error) {
	rs, ok := p.rulesets[rulesetKey(rulesetID, rulesetVersion)]
	if !ok {
		return rule.RuleResult{}, fmt.Errorf("ruleset with id %s and version %s does not exist", rulesetID, rulesetVersion)
	}

	return rs.RunRule(ctx, ruleID)
}

// AddRulesets adds Rulesets to Provider.
func (p *Provider) AddRulesets(rulesets ...ruleset.Ruleset) error {
	for _, r := range rulesets {
		key := rulesetKey(r.ID(), r.Version())
		if _, ok := p.rulesets[key]; ok {
			return fmt.Errorf("ruleset with id %s and version %s already exists", r.ID(), r.Version())
		}
		p.rulesets[key] = r
	}
	return nil
}

// ID returns the id of the Provider.
func (p *Provider) ID() string {
	return p.id
}

// Name returns the name of the Provider.
func (p *Provider) Name() string {
	return p.name
}

// Metadata returns the metadata of the Provider.
func (p *Provider) Metadata() map[string]string {
	if p.metadata == nil {
		p.metadata = map[string]string{}
	}
	return p.metadata
}

// FromGenericConfig creates a Provider from ProviderConfig.
func FromGenericConfig(providerConf config.ProviderConfig) (*Provider, error) {
	providerArgsByte, err := json.Marshal(providerConf.Args)
	if err != nil {
		return nil, err
	}

	var providerGardenArgs providerArgs
	if err := json.Unmarshal(providerArgsByte, &providerGardenArgs); err != nil {
		return nil, err
	}

	runtimeKubeconfig, err := kubeutils.RESTConfigFromFile(providerGardenArgs.RuntimeKubeconfigPath)
	if err != nil {
		return nil, err
	}

	gardenProvider, err := New(
		WithID(providerConf.ID),
		WithName(providerConf.Name),
		WithOpsPodLabels(providerGardenArgs.OpsPodLabels),
		WithRuntimeConfig(runtimeKubeconfig),
		WithMetadata(providerConf.Metadata),
	)
	if err != nil {
		return nil, err
	}

	return gardenProvider, nil
}

// Logger returns the Provider's logger.
// If not set it set it to slog.Default().With("provider", p.ID()) then return it.
func (p *Provider) Logger() *slog.Logger {
	if p.logger == nil {
		p.logger = slog.Default().With("provider", p.ID())
	}
	return p.logger
}
