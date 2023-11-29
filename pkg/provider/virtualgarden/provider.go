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
	"maps"

	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
)

// Provider is a Garden Cluster Provider that can be used to implement rules
// against a virtual garden cluster and its controlplane (residing in a runtime cluster).
type Provider struct {
	id, name                    string
	RuntimeConfig, GardenConfig *rest.Config
	rulesets                    map[string]ruleset.Ruleset
	metadata                    map[string]string
	logger                      *slog.Logger
}

type providerArgs struct {
	RuntimeKubeconfigPath string
	GardenKubeconfigPath  string
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

	if p.GardenConfig == nil {
		err = errors.Join(err, errors.New("garden cluster config is nil"))
	}

	if err != nil {
		return nil, err
	}

	return p, nil
}

// RunAll executes all Rulesets registered with the Provider.
func (p *Provider) RunAll(ctx context.Context) (provider.ProviderResult, error) {
	if len(p.rulesets) == 0 {
		return provider.ProviderResult{}, fmt.Errorf("no rulests are registered with the provider")
	}

	result := provider.ProviderResult{
		ProviderName:   p.Name(),
		ProviderID:     p.ID(),
		Metadata:       maps.Clone(p.Metadata()),
		RulesetResults: make([]ruleset.RulesetResult, 0, len(p.rulesets)),
	}

	var errAgg error
	p.Logger().Info(fmt.Sprintf("provider will run %d rulesets", len(p.rulesets)))
	for _, rs := range p.rulesets {
		p.Logger().Info(fmt.Sprintf("starting run of ruleset %s version %s", rs.ID(), rs.Version()))
		if res, err := rs.Run(ctx); err != nil {
			errAgg = errors.Join(errAgg, fmt.Errorf("ruleset with id %s and version %s errored: %w", res.RulesetID, res.RulesetVersion, err))
			p.Logger().Error(fmt.Sprintf("finished ruleset %s version %s run", rs.ID(), rs.Version()), "error", err)
		} else {
			result.RulesetResults = append(result.RulesetResults, res)
			p.Logger().Info(fmt.Sprintf("finished ruleset %s version %s run", rs.ID(), rs.Version()))
		}
	}

	if errAgg != nil {
		return provider.ProviderResult{}, errAgg
	}
	return result, nil
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

	GardenKubeconfig, err := kubeutils.RESTConfigFromFile(providerGardenArgs.GardenKubeconfigPath)
	if err != nil {
		return nil, err
	}

	gardenProvider, err := New(
		WithID(providerConf.ID),
		WithName(providerConf.Name),
		WithGardenConfig(GardenKubeconfig),
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
