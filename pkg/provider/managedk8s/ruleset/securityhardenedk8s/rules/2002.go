// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

	kubeutils.GetPods(ctx, r.Client)

}
