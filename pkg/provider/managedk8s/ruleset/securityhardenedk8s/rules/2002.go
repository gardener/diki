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
	_ rule.Rule          = &Rule2002{}
	_ rule.Severity      = &Rule2002{}
	_ disaoptions.Option = &Options2002{}
)

type Rule2002 struct {
	Client  client.Client
	Options *Options2002
}

type Options2002 struct {
	AcceptedStorageClasses []option.AcceptedClusterObject `json:"acceptedStorageClasses" yaml:"acceptedStorageClasses"`
}

// Validate validates that option configurations are correctly defined
func (o Options2002) Validate(fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	acceptedStorageClassesPath := fldPath.Child("acceptedStorageClasses")

	for scIdx, sc := range o.AcceptedStorageClasses {
		allErrs = append(allErrs, sc.Validate(acceptedStorageClassesPath.Index(scIdx))...)
	}

	return allErrs
}

func (r *Rule2002) ID() string {
	return "2002"
}

func (r *Rule2002) Name() string {
	return "Storage Classes should have a \"Delete\" reclaim policy."
}

func (r *Rule2002) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule2002) Run(ctx context.Context) (rule.RuleResult, error) {
	storageClasses, err := kubeutils.GetStorageClasses(ctx, r.Client, labels.NewSelector(), 300)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "StorageClassList"))), nil
	}

	if len(storageClasses) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any StorageClasses.", rule.NewTarget())), nil
	}

	var checkResults []rule.CheckResult

	for _, storageClass := range storageClasses {
		target := kubeutils.TargetWithK8sObject(rule.NewTarget(), v1.TypeMeta{Kind: "StorageClass"}, storageClass.ObjectMeta)

		if storageClass.ReclaimPolicy != nil && *storageClass.ReclaimPolicy == corev1.PersistentVolumeReclaimDelete {
			checkResults = append(checkResults, rule.PassedCheckResult("StorageClass has a Delete ReclaimPolicy set.", target))
			continue
		}

		if accepted, justification := r.accepted(storageClass.Labels); accepted {
			msg := cmp.Or(justification, "StorageClass accepted to not have Delete ReclaimPolicy.")
			checkResults = append(checkResults, rule.AcceptedCheckResult(msg, target))
		} else {
			checkResults = append(checkResults, rule.FailedCheckResult("StorageClass does not have a Delete ReclaimPolicy set.", target))
		}
	}

	return rule.Result(r, checkResults...), err
}

func (r *Rule2002) accepted(storageClassLabels map[string]string) (bool, string) {
	if r.Options == nil {
		return false, ""
	}

	for _, acceptedStorageClass := range r.Options.AcceptedStorageClasses {
		if utils.MatchLabels(storageClassLabels, acceptedStorageClass.MatchLabels) {
			return true, acceptedStorageClass.Justification
		}
	}

	return false, ""
}
