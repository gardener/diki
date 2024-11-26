// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2006{}
	_ rule.Severity = &Rule2006{}
)

type Rule2006 struct {
	Client client.Client
}

func (r *Rule2006) ID() string {
	return "2006"
}

func (r *Rule2006) Name() string {
	return "Limit the use of wildcards in RBAC resources."
}

func (r *Rule2006) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule2006) Run(ctx context.Context) (rule.RuleResult, error) {
	roles, err := kubeutils.GetRoles(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "rolesList"))), nil
	}

	clusterRoles, err := kubeutils.GetClusterRoles(ctx, r.Client, labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "clusterRolesList"))), nil
	}

	var (
		checkResults []rule.CheckResult
		checkRules   = func(policyRules []rbacv1.PolicyRule, target rule.Target) rule.CheckResult {
			for _, policyRule := range policyRules {
				for _, resource := range policyRule.Resources {
					if strings.Contains(resource, "*") {
						return rule.FailedCheckResult("Found \"*\" in policyRule resources.", target)
					}
				}
			}
			return rule.PassedCheckResult("Did not find \"*\" in policyRule resources.", target)
		}
	)

	for _, role := range roles {
		target := rule.NewTarget("kind", "role", "name", role.Name, "namespace", role.Namespace)
		checkResults = append(checkResults, checkRules(role.Rules, target))
	}

	for _, clusterRole := range clusterRoles {
		target := rule.NewTarget("kind", "clusterRole", "name", clusterRole.Name)
		checkResults = append(checkResults, checkRules(clusterRole.Rules, target))
	}

	return rule.Result(r, checkResults...), nil
}
