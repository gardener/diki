// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
func (o Options2006) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	for rIdx, r := range o.AcceptedRoles {
		allErrs = append(allErrs, r.Validate(fldPath.Child("acceptedRoles").Index(rIdx))...)
	}

	for cIdx, c := range o.AcceptedClusterRoles {
		allErrs = append(allErrs, c.Validate(fldPath.Child("acceptedClusterRoles").Index(cIdx))...)
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

		accepted, justification, err := r.acceptedRole(role.Labels, namespaces[role.Namespace].Labels)
		if err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), err
		}
		checkResults = append(checkResults, checkRules(role.Rules, accepted, justification, target))
	}

	for _, clusterRole := range clusterRoles {
		target := kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "ClusterRole"}, clusterRole.ObjectMeta)

		accepted, justification, err := r.acceptedClusterRole(clusterRole.Labels)
		if err != nil {
			return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget())), err
		}
		checkResults = append(checkResults, checkRules(clusterRole.Rules, accepted, justification, target))
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule2006) acceptedRole(roleLabels, namespaceLabels map[string]string) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedRole := range r.Options.AcceptedRoles {
		if matches, err := acceptedRole.Matches(roleLabels, namespaceLabels); err != nil {
			return false, "", err
		} else if matches {
			return true, acceptedRole.Justification, nil
		}
	}

	return false, "", nil
}

func (r *Rule2006) acceptedClusterRole(clusterRoleLabels map[string]string) (bool, string, error) {
	if r.Options == nil {
		return false, "", nil
	}

	for _, acceptedClusterRole := range r.Options.AcceptedClusterRoles {
		if matches, err := acceptedClusterRole.Matches(clusterRoleLabels); err != nil {
			return false, "", err
		} else if matches {
			return true, acceptedClusterRole.Justification, nil
		}
	}

	return false, "", nil
}
