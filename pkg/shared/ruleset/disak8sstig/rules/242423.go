// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/kubernetes/config"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242423{}
	_ rule.Severity = &Rule242423{}
)

type Rule242423 struct {
	Client                client.Client
	Namespace             string
	StatefulSetETCDMain   string
	StatefulSetETCDEvents string
}

func (r *Rule242423) ID() string {
	return ID242423
}

func (r *Rule242423) Name() string {
	return "Kubernetes etcd must enable client authentication to secure service."
}

func (r *Rule242423) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242423) Run(ctx context.Context) (rule.RuleResult, error) {
	var checkResults []rule.CheckResult
	etcdMain := "etcd-main"
	etcdEvents := "etcd-events"

	if r.StatefulSetETCDMain != "" {
		etcdMain = r.StatefulSetETCDMain
	}

	if r.StatefulSetETCDEvents != "" {
		etcdEvents = r.StatefulSetETCDEvents
	}
	checkResults = append(checkResults, r.checkStatefulSet(ctx, etcdMain))
	checkResults = append(checkResults, r.checkStatefulSet(ctx, etcdEvents))

	return rule.Result(r, checkResults...), nil
}

func (r *Rule242423) checkStatefulSet(ctx context.Context, statefulSetName string) rule.CheckResult {
	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      statefulSetName,
			Namespace: r.Namespace,
		},
	}

	target := rule.NewTarget("name", statefulSetName, "namespace", r.Namespace, "kind", "statefulSet")

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(statefulSet), statefulSet); err != nil {
		return rule.ErroredCheckResult(err.Error(), target)
	}

	volume, found := kubeutils.GetVolumeFromStatefulSet(statefulSet, "etcd-config-file")
	if !found {
		return rule.ErroredCheckResult("StatefulSet does not contain volume with name: etcd-config-file.", target)
	}

	configByteSlice, err := kubeutils.GetFileDataFromVolume(ctx, r.Client, r.Namespace, volume, "etcd.conf.yaml")
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), target)
	}

	config := &config.EtcdConfig{}
	err = yaml.Unmarshal(configByteSlice, config)
	if err != nil {
		return rule.ErroredCheckResult(err.Error(), target)
	}

	if config.ClientTransportSecurity.CertAuth == nil {
		return rule.WarningCheckResult("Option client-transport-security.client-cert-auth has not been set.", target)
	}
	if *config.ClientTransportSecurity.CertAuth {
		return rule.PassedCheckResult("Option client-transport-security.client-cert-auth set to allowed value.", target)
	}

	return rule.FailedCheckResult("Option client-transport-security.client-cert-auth set to not allowed value.", target)
}
