// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Masterminds/semver"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242437{}

type Rule242437 struct {
	ClusterClient         client.Client
	ClusterVersion        *semver.Version
	ControlPlaneClient    client.Client
	ControlPlaneVersion   *semver.Version
	ControlPlaneNamespace string
	Logger                *slog.Logger
}

func (r *Rule242437) ID() string {
	return ID242437
}

func (r *Rule242437) Name() string {
	return "Kubernetes must have a pod security policy set (HIGH 242437)"
}

func (r *Rule242437) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}
	if versionutils.ConstraintK8sGreaterEqual125.Check(r.ControlPlaneVersion) {
		checkResults = append(checkResults, rule.SkippedCheckResult("Pod security policies dropped with Kubernetes v1.25.",
			gardener.NewTarget("cluster", "seed", "details", fmt.Sprintf("Cluster uses Kubernetes %s.", r.ControlPlaneVersion.String()))))
	} else {
		seedPodSecurityPolicies, err := kubeutils.GetPodSecurityPolicies(ctx, r.ControlPlaneClient, 300)
		if err != nil {
			return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget("cluster", "seed", "namespace", r.ControlPlaneNamespace, "kind", "podSecurityPolicyList"))), nil
		}

		checkResults = r.checkPodSecurityPolicies(seedPodSecurityPolicies, "seed")
	}

	if versionutils.ConstraintK8sGreaterEqual125.Check(r.ClusterVersion) {
		checkResults = append(checkResults, rule.SkippedCheckResult("Pod security policies dropped with Kubernetes v1.25.",
			gardener.NewTarget("cluster", "shoot", "details", fmt.Sprintf("Cluster uses Kubernetes %s.", r.ControlPlaneVersion.String()))))
	} else {
		shootPodSecurityPolicies, err := kubeutils.GetPodSecurityPolicies(ctx, r.ClusterClient, 300)
		if err != nil {
			return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), gardener.NewTarget("cluster", "shoot", "namespace", r.ControlPlaneNamespace, "kind", "podSecurityPolicyList"))), nil
		}

		checkResults = append(checkResults, r.checkPodSecurityPolicies(shootPodSecurityPolicies, "shoot")...)
	}

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (*Rule242437) checkPodSecurityPolicies(podSecurityPolicies []policyv1beta1.PodSecurityPolicy, cluster string) []rule.CheckResult {
	checkResults := []rule.CheckResult{}
	target := gardener.NewTarget("cluster", cluster)
	if len(podSecurityPolicies) == 0 {
		return []rule.CheckResult{rule.FailedCheckResult("No pod security policies(PSPs) found.", target)}
	}
	for _, podSecurityPolicy := range podSecurityPolicies {
		failedCheck := false
		pspTarget := target.With("name", podSecurityPolicy.Name, "kind", "podSecurityPolicy")

		if len(podSecurityPolicy.Spec.FSGroup.Ranges) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult("Pod security policy fs group ranges are not set.", pspTarget))
			failedCheck = true
		}

		for _, fsGroupRange := range podSecurityPolicy.Spec.FSGroup.Ranges {
			if fsGroupRange.Min == 0 {
				checkResults = append(checkResults, rule.FailedCheckResult("Pod security policy fs group range not excluding 0.", pspTarget))
				failedCheck = true
				break
			}
		}

		if len(podSecurityPolicy.Spec.SupplementalGroups.Ranges) == 0 {
			checkResults = append(checkResults, rule.FailedCheckResult("Pod security policy supplemental group ranges are not set.", pspTarget))
			failedCheck = true
		}

		for _, supplementalGroupRange := range podSecurityPolicy.Spec.SupplementalGroups.Ranges {
			if supplementalGroupRange.Min == 0 {
				checkResults = append(checkResults, rule.FailedCheckResult("Pod security policy supplemental group range not excluding 0.", pspTarget))
				failedCheck = true
				break
			}
		}

		if podSecurityPolicy.Spec.RunAsUser.Rule != policyv1beta1.RunAsUserStrategyMustRunAsNonRoot {
			checkResults = append(checkResults, rule.FailedCheckResult(fmt.Sprintf("Pod security policy run user not defined as %s.", policyv1beta1.RunAsUserStrategyMustRunAsNonRoot), pspTarget))
			failedCheck = true
		}

		if !failedCheck {
			checkResults = append(checkResults, rule.PassedCheckResult("Pod security policy correctly configured.", pspTarget))
		}
	}

	return checkResults
}
