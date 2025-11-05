// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"fmt"
	"reflect"

	"go.yaml.in/yaml/v4"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242403{}
	_ rule.Severity = &Rule242403{}
)

type Rule242403 struct {
	Client         client.Client
	Namespace      string
	DeploymentName string
}

func (r *Rule242403) ID() string {
	return ID242403
}

func (r *Rule242403) Name() string {
	return "The Kubernetes API Server must generate audit records that identify what type of event has occurred, identify the source of the event, contain the event results, identify any users, and identify any containers associated with the event."
}

func (r *Rule242403) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242403) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		mountName = "audit-policy-config"
		fileName  = "audit-policy.yaml"
	)
	deploymentName := "kube-apiserver"

	if r.DeploymentName != "" {
		deploymentName = r.DeploymentName
	}

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Namespace: r.Namespace,
		},
	}

	target := rule.NewTarget("kind", "Deployment", "name", deploymentName, "namespace", r.Namespace)

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(deployment), deployment); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	volume, found := kubeutils.GetVolumeFromDeployment(deployment, mountName)
	if !found {
		return rule.Result(r, rule.ErroredCheckResult(fmt.Sprintf("Deployment does not contain volume with name: %s.", mountName), target)), nil
	}

	auditPolicyByteSlice, err := kubeutils.GetFileDataFromVolume(ctx, r.Client, r.Namespace, volume, fileName)
	if err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	auditPolicy := &auditv1.Policy{}
	if err = yaml.Unmarshal(auditPolicyByteSlice, auditPolicy); err != nil {
		return rule.Result(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if r.isPolicyConformant(auditPolicy) {
		return rule.Result(r, rule.PassedCheckResult("Audit log policy file is conformant with required specification.", target)), nil
	}

	return rule.Result(r, rule.FailedCheckResult("Audit log policy file is not conformant with required specification.", target)), nil
}

func (r *Rule242403) isPolicyConformant(auditPolicy *auditv1.Policy) bool {
	allowedAuiditPolicyRule := auditv1.PolicyRule{
		Level: auditv1.LevelRequestResponse,
	}

	return len(auditPolicy.Rules) == 1 &&
		reflect.DeepEqual(auditPolicy.Rules[0], allowedAuiditPolicyRule)
}
