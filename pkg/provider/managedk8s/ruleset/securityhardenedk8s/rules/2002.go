// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule2002{}
	_ rule.Severity = &Rule2002{}
)

type Rule2002 struct {
	Client client.Client
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
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), rule.NewTarget("kind", "storageClassList"))), nil
	}

	if len(storageClasses) == 0 {
		return rule.Result(r, rule.PassedCheckResult("The cluster does not have any StorageClasses.", rule.NewTarget())), nil
	}

	var checkResults []rule.CheckResult

	for _, storageClass := range storageClasses {
		target := rule.NewTarget("kind", "storageClass", "name", storageClass.Name)
		switch {
		case storageClass.ReclaimPolicy == nil:
			checkResults = append(checkResults, rule.FailedCheckResult("StorageClass does not have a configured ReclaimPolicy.", target))
		case storageClass.ReclaimPolicy != nil && *storageClass.ReclaimPolicy == corev1.PersistentVolumeReclaimDelete:
			checkResults = append(checkResults, rule.PassedCheckResult("StorageClass has a Delete ReclaimPolicy set.", target))
		default:
			checkResults = append(checkResults, rule.FailedCheckResult("StorageClass does not have a Delete ReclaimPolicy set.", target))
		}
	}

	return rule.Result(r, checkResults...), err
}
