// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"cmp"
	"context"

	corev1 "k8s.io/api/core/v1"
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
	_ rule.Rule          = &Rule2004{}
	_ rule.Severity      = &Rule2004{}
	_ disaoptions.Option = &Options2004{}
)

type Rule2004 struct {
	Client  client.Client
	Options *Options2004
}

type Options2004 struct {
	AcceptedServices []option.AcceptedNamespacedObject `json:"acceptedServices" yaml:"acceptedServices"`
}

// Validate validates that option configurations are correctly defined.
func (o Options2004) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedServicesPath := fldPath.Child("acceptedServices")

	for sIdx, s := range o.AcceptedServices {
		allErrs = append(allErrs, s.Validate(acceptedServicesPath.Index(sIdx))...)
	}

	return allErrs
}

func (r *Rule2004) ID() string {
	return "2004"
}

func (r *Rule2004) Name() string {
	return "Limit the Services of type NodePort."
}

func (r *Rule2004) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule2004) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult

	services, err := kubeutils.GetServices(ctx, r.Client, "", labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "ServiceList"))), nil
	}

	if len(services) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any Services.", rule.NewTarget())), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "NamespaceList"))), nil
	}

	for _, service := range services {
		serviceTarget := kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "Service"}, service.ObjectMeta)

		if service.Spec.Type == corev1.ServiceTypeNodePort {
			if accepted, justification := r.accepted(service, namespaces[service.Namespace]); accepted {
				msg := cmp.Or(justification, "Service accepted to be of type NodePort.")
				checkResults = append(checkResults, rule.AcceptedCheckResult(msg, serviceTarget))
			} else {
				checkResults = append(checkResults, rule.FailedCheckResult("Service should not be of type NodePort.", serviceTarget))
			}
		} else {
			checkResults = append(checkResults, rule.PassedCheckResult("Service is not of type NodePort.", serviceTarget))
		}
	}

	return rule.Result(r, checkResults...), nil
}

func (r *Rule2004) accepted(service corev1.Service, namespace corev1.Namespace) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedService := range r.Options.AcceptedServices {
		if utils.MatchLabels(service.Labels, acceptedService.MatchLabels) &&
			utils.MatchLabels(namespace.Labels, acceptedService.NamespaceMatchLabels) {
			return true, acceptedService.Justification
		}
	}

	return false, ""
}
