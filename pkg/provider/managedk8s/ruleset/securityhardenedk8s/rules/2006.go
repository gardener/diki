// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"strings"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/internal/utils"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"github.com/gardener/diki/pkg/shared/kubernetes/option"
	disaoptions "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/option"
)

var (
	_ rule.Rule          = &Rule2006{}
	_ rule.Severity      = &Rule2006{}
	_ disaoptions.Option = &Options2006{}
)

type Rule2006 struct {
	Client  client.Client
	Options *Options2006
}

type Options2006 struct {
	AcceptedRoles        []option.AcceptedNamespacedObject `json:"acceptedRoles" yaml:"acceptedRoles"`
	AcceptedClusterRoles []option.AcceptedClusterObject    `json:"acceptedClusterRoles" yaml:"acceptedClusterRoles"`
}

// Validate validates that option configurations are correctly defined.
func (o Options2006) Validate() field.ErrorList {
	var allErrs field.ErrorList

	for _, r := range o.AcceptedRoles {
		allErrs = append(allErrs, r.Validate()...)
	}

	for _, c := range o.AcceptedClusterRoles {
		allErrs = append(allErrs, c.Validate()...)
	}

	return allErrs
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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "RolesList"))), nil
	}

	clusterRoles, err := kubeutils.GetClusterRoles(ctx, r.Client, labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ClusterRolesList"))), nil
	}

	if len(roles) == 0 && len(clusterRoles) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any Roles or ClusterRoles.", rule.NewTarget())), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NamespaceList"))), nil
	}

	var (
		checkResults []rule.CheckResult
		checkRules   = func(policyRules []rbacv1.PolicyRule, accepted bool, justification string, target rule.Target) rule.CheckResult {
			msg := cmp.Or(justification, "Role is accepted to use \"*\" in policy rule resources.")

			for _, policyRule := range policyRules {
				for _, resource := range policyRule.Resources {
					if strings.Contains(resource, "*") {
						if accepted {
							return rule.AcceptedCheckResult(msg, target)
						}
						return rule.FailedCheckResult("Role uses \"*\" in policy rule resources.", target)
					}
				}
			}
			return rule.PassedCheckResult("Role does not use \"*\" in policy rule resources.", target)
		}
	)

	for _, role := range roles {
		target := kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "Role"}, role.ObjectMeta)

		accepted, justification := r.acceptedRole(role, namespaces[role.Namespace])
		checkResults = append(checkResults, checkRules(role.Rules, accepted, justification, target))
	}

	for _, clusterRole := range clusterRoles {
		target := kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "ClusterRole"}, clusterRole.ObjectMeta)

		accepted, justification := r.acceptedClusterRole(clusterRole)
		checkResults = append(checkResults, checkRules(clusterRole.Rules, accepted, justification, target))
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule2006) acceptedRole(role rbacv1.Role, namespace corev1.Namespace) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedRole := range r.Options.AcceptedRoles {
		if utils.MatchLabels(role.Labels, acceptedRole.MatchLabels) &&
			utils.MatchLabels(namespace.Labels, acceptedRole.NamespaceMatchLabels) {
			return true, acceptedRole.Justification
		}
	}

	return false, ""
}

func (r *Rule2006) acceptedClusterRole(clusterRole rbacv1.ClusterRole) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedClusterRoles := range r.Options.AcceptedClusterRoles {
		if utils.MatchLabels(clusterRole.Labels, acceptedClusterRoles.MatchLabels) {
			return true, acceptedClusterRoles.Justification
		}
	}

	return false, ""
}
