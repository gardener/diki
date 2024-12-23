// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	corev1 "k8s.io/api/core/v1"
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

// Validate validates that option configurations are correctly defined
func (o Options2004) Validate() field.ErrorList {
	var allErrs field.ErrorList

	for _, s := range o.AcceptedServices {
		allErrs = append(allErrs, s.Validate()...)
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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "serviceList"))), nil
	}

	if len(services) == 0 {
		return rule.Result(r, rule.PassedCheckResult("There are no services for evaluation.", rule.NewTarget())), nil
	}

	namespaces, err := kubeutils.GetNamespaces(ctx, r.Client)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "namespaceList"))), nil
	}

	for _, service := range services {
		serviceTarget := rule.NewTarget("kind", "service", "name", service.Name, "namespace", service.Namespace)

		if service.Spec.Type == corev1.ServiceTypeNodePort {
			if accepted, justification := r.accepted(service, namespaces[service.Namespace]); accepted {
				msg := "Service accepted to be of type NodePort."
				if justification != "" {
					msg = justification
				}
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
