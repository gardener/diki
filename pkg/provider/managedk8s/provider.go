// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package managedk8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"k8s.io/client-go/tools/clientcmd"

	"k8s.io/client-go/rest"

	"github.com/gardener/diki/pkg/config"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/ruleset"
	sharedprovider "github.com/gardener/diki/pkg/shared/provider"
)

const (
	// ProviderID is a constant containing the id of the Managed Kubernetes provider.
	ProviderID = "managedk8s"
	// ProviderName is a constant containing the user-friendly name of the Managed Kubernetes provider.
	ProviderName = "Managed Kubernetes"
)

// Provider is a Managed Kubernetes Cluster Provider that can
// be used to implement rules against a kubernetes cluster.
type Provider struct {
	id, name               string
	AdditionalOpsPodLabels map[string]string
	Config                 *rest.Config
	rulesets               map[string]ruleset.Ruleset
	metadata               map[string]string
	logger                 sharedprovider.Logger
}

type providerArgs struct {
	AdditionalOpsPodLabels map[string]string `json:"additionalOpsPodLabels" yaml:"additionalOpsPodLabels"`
	KubeconfigPath         string            `json:"kubeconfigPath" yaml:"kubeconfigPath"`
}

type ConfigOptions struct {
	ConfigGetter inClusterConfigGetter
}

type inClusterConfigGetter func() (*rest.Config, error)

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
	if p.Config == nil {
		err = errors.Join(err, errors.New("cluster config is nil"))
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
func FromGenericConfig(providerConf config.ProviderConfig, options ConfigOptions) (*Provider, error) {
	providerArgsByte, err := json.Marshal(providerConf.Args)
	if err != nil {
		return nil, err
	}

	var providerArgs providerArgs
	if err := json.Unmarshal(providerArgsByte, &providerArgs); err != nil {
		return nil, err
	}

	kubeconfig, err := loadConfig(providerArgs, options)
	if err != nil {
		return nil, err
	}

	provider, err := New(
		WithID(providerConf.ID),
		WithName(providerConf.Name),
		WithAdditionalOpsPodLabels(providerArgs.AdditionalOpsPodLabels),
		WithConfig(kubeconfig),
		WithMetadata(providerConf.Metadata),
	)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

// Logger returns the Provider's logger.
// If not set it set it to slog.Default().With("provider", p.ID()) then return it.
func (p *Provider) Logger() sharedprovider.Logger {
	if p.logger == nil {
		p.logger = slog.Default().With("provider", p.ID())
	}
	return p.logger
}

func loadConfig(providerArgs providerArgs, options ConfigOptions) (config *rest.Config, err error) {

	var kubeconfig *rest.Config

	// Check if a kubeconfig path is provided via the provider args in the configuration file.
	if len(providerArgs.KubeconfigPath) > 0 {
		kubeconfig, err = kubeutils.RESTConfigFromFile(providerArgs.KubeconfigPath)
		if err == nil {
			fmt.Print("kubeconfig path from args: ", providerArgs.KubeconfigPath)
			fmt.Print("kubeconfig: ", kubeconfig)
			return kubeconfig, nil
		}
	}

	// If no kubeconfigPath is set in the provider args,
	// check if a kubeconfig path is provided via the KUBECONFIG environment variable.
	kubeconfigPath := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if len(kubeconfigPath) > 0 {
		kubeconfig, err = kubeutils.RESTConfigFromFile(kubeconfigPath)
		if err == nil {
			fmt.Print("kubeconfig from env: ", providerArgs.KubeconfigPath)
			fmt.Print("kubeconfig: ", kubeconfig)
			return kubeconfig, nil
		}
	}

	// If no kubeconfigPath is set in the provider args or via the KUBECONFIG environment variable,
	//  try to use in-cluster configuration.
	if options.ConfigGetter != nil {
		kubeconfig, err = options.ConfigGetter()
	} else {
		kubeconfig, err = rest.InClusterConfig()
	}
	if err == nil {
		fmt.Print("kubeconfig from Cluster")
		fmt.Print("kubeconfig: ", kubeconfig)
		kubeconfig.CAData, err = os.ReadFile(kubeconfig.CAFile)
		if err == nil {
			return kubeconfig, nil
		}
	}

	return nil, err
}
