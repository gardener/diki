// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package podsecuritystandards

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/diki/pkg/config"
	internalconfig "github.com/gardener/diki/pkg/internal/config"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/podsecuritystandards/rules"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
)

func (r *Ruleset) validateV01RuleOptions(ruleOptions map[string]internalconfig.IndexedRuleOptionsConfig, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}

	allErrs = append(allErrs, validateV01Options[rules.OptionsPSSB001](ruleOptions["PSS-B001"].Args, fldPath.Index(ruleOptions["PSS-B001"].Index).Child("args"))...)

	return allErrs
}

func (r *Ruleset) registerV01Rules(ruleOptions map[string]config.RuleOptionsConfig) error {
	rules := []rule.Rule{
		rule.NewSkipRule(
			"PSS-B001",
			"Windows Pods offer the ability to run Host Process containers which enables privileged access to the Windows host machine. Privileged access to the host is disallowed in the Baseline policy.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B002",
			"Sharing the host namespaces must be disallowed.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B003",
			"Privileged Pods disable most security mechanisms and must be disallowed.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B004",
			"Adding additional capabilities beyond the following must be disallowed: AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD, NET_BIND_SERVICE, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B005",
			"Host Path volumes must be forbidden.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B006",
			"Host Ports should be disallowed entirely (recommended) or restricted to a known list.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B007",
			"The host field in probes and lifecycle hooks must be disallowed.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B008",
			"On supported hosts, the RuntimeDefault AppArmor profile is applied by default. The Baseline policy should prevent overriding or disabling the default AppArmor profile, or restrict overrides to an allowed set of profiles.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B009",
			"Setting the SELinux type is restricted, and setting a custom SELinux user or role option is forbidden.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B010",
			"The default /proc masks are set up to reduce attack surface, and should be required.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B011",
			"Seccomp profile must not be explicitly set to Unconfined.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-B012",
			"Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed \"safe\" subset. A sysctl is considered safe if it is namespaced in the container or the Pod, and it is isolated from other Pods or processes on the same Node.",
			"Not implemented.",
			rule.NotImplemented,
		),

		rule.NewSkipRule(
			"PSS-R001",
			"The Restricted policy only permits the following volume types: configMap, csi, downwardAPI, emptyDir, ephemeral, persistentVolumeClaim, projected, secret.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R002",
			"Privilege escalation (such as via set-user-ID or set-group-ID file mode) should not be allowed. This is Linux only policy in v1.25+.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R003",
			"Containers must be required to run as non-root users.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R004",
			"Containers must not set runAsUser to 0.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R005",
			"Seccomp profile must be explicitly set to RuntimeDefault or Localhost. Unconfined profiles and the absence of a profile are prohibited.",
			"Not implemented.",
			rule.NotImplemented,
		),
		rule.NewSkipRule(
			"PSS-R006",
			"Containers must drop ALL capabilities, and are only permitted to add back NET_BIND_SERVICE.",
			"Not implemented.",
			rule.NotImplemented,
		),
	}

	for i, r := range rules {
		opt, found := ruleOptions[r.ID()]
		if found && opt.Skip != nil && opt.Skip.Enabled {
			rules[i] = rule.NewSkipRule(r.ID(), r.Name(), opt.Skip.Justification, rule.Accepted)
		}
	}

	// check that the registered rules equal
	// the number of rules in that ruleset version
	expectedRules := 18
	if len(rules) != expectedRules {
		return fmt.Errorf("revision expects %d registered rules, but got: %d", expectedRules, len(rules))
	}

	return r.AddRules(rules...)
}

func validateV01Options[O rules.RuleOption](options any, fldPath *field.Path) field.ErrorList {
	parsedOptions, err := getV01OptionOrNil[O](options)
	if err != nil {
		return field.ErrorList{
			field.Invalid(fldPath, options, err.Error()),
		}
	}

	if parsedOptions == nil {
		return nil
	}

	if val, ok := any(parsedOptions).(option.Option); ok {
		return val.Validate(fldPath)
	}

	return nil
}

func parseV01Options[O rules.RuleOption](options any) (*O, error) {
	optionsByte, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	var parsedOptions O
	if err := json.Unmarshal(optionsByte, &parsedOptions); err != nil {
		return nil, err
	}

	return &parsedOptions, nil
}

func getV01OptionOrNil[O rules.RuleOption](options any) (*O, error) {
	if options == nil {
		return nil, nil
	}
	return parseV01Options[O](options)
}
