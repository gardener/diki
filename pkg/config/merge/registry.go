// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"encoding/json"
	"fmt"

	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

// RegistryKey uniquely identifies a rule option type within a specific provider, ruleset, and version.
type RegistryKey struct {
	ProviderID string
	RulesetID  string
	Version    string
	RuleID     string
}

// RuleOptionMergeFunc merges base args with custom args for a specific rule.
// If the option type implements MergeableOption, it calls Merge; otherwise it returns customArgs unchanged.
type RuleOptionMergeFunc func(baseArgs, customArgs any) (any, error)

// Registry maps rule option types to their merge functions.
type Registry struct {
	funcs map[RegistryKey]RuleOptionMergeFunc
}

// NewRegistry creates a new empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		funcs: make(map[RegistryKey]RuleOptionMergeFunc),
	}
}

// Register adds a merge function for a given key.
func (r *Registry) Register(key RegistryKey, fn RuleOptionMergeFunc) {
	r.funcs[key] = fn
}

// Get retrieves the merge function for a given key, or nil if not registered.
func (r *Registry) Get(key RegistryKey) RuleOptionMergeFunc {
	return r.funcs[key]
}

// RegisterMergeFunc registers a typed merge function for the given key.
// It parses raw args into the concrete type O and checks if it implements MergeableOption.
func RegisterMergeFunc[O any](r *Registry, key RegistryKey) {
	r.Register(key, func(baseArgs, customArgs any) (any, error) {
		baseOpt, err := parseOption[O](baseArgs)
		if err != nil {
			return nil, fmt.Errorf("failed to parse base args for rule %s: %w", key.RuleID, err)
		}

		customOpt, err := parseOption[O](customArgs)
		if err != nil {
			return nil, fmt.Errorf("failed to parse custom args for rule %s: %w", key.RuleID, err)
		}

		baseMergeable, ok := any(baseOpt).(option.MergeableOption)
		if !ok {
			return customArgs, nil
		}

		customMergeable, ok := any(customOpt).(option.MergeableOption)
		if !ok {
			return customArgs, nil
		}

		merged, err := baseMergeable.Merge(customMergeable)
		if err != nil {
			return nil, fmt.Errorf("failed to merge args for rule %s: %w", key.RuleID, err)
		}

		return toRawMap(merged)
	})
}

func parseOption[O any](args any) (*O, error) {
	if args == nil {
		return nil, nil
	}

	data, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}

	var opt O
	if err := json.Unmarshal(data, &opt); err != nil {
		return nil, err
	}

	return &opt, nil
}

func toRawMap(v any) (any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	return raw, nil
}
