// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"strings"

	"go.yaml.in/yaml/v4"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/kubernetes/config"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/rule"
)

var (
	_ rule.Rule     = &Rule242432{}
	_ rule.Severity = &Rule242432{}
)

type Rule242432 struct {
	Client                client.Client
	Namespace             string
	StatefulSetETCDMain   string
	StatefulSetETCDEvents string
}

func (r *Rule242432) ID() string {
	return ID242432
}

func (r *Rule242432) Name() string {
	return "Kubernetes etcd must have peer-cert-file set for secure communication."
}

func (r *Rule242432) Severity() rule.SeverityLevel {
	return rule.SeverityMedium
}

func (r *Rule242432) Run(ctx context.Context) (rule.RuleResult, error) {
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

func (r *Rule242432) checkStatefulSet(ctx context.Context, statefulSetName string) rule.CheckResult {
	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      statefulSetName,
			Namespace: r.Namespace,
		},
	}

	target := kubeutils.TargetWithK8sObject(rule.NewTarget(), metav1.TypeMeta{Kind: "StatefulSet"}, statefulSet.ObjectMeta)

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

	// We do not check the command-line flags and environment variables,
	// since they are ignored when a config file is set. ref https://etcd.io/docs/v3.5/op-guide/configuration/
	if len(strings.Split(config.InitialCluster, ",")) == 1 {
		return rule.SkippedCheckResult("ETCD runs as a single instance, peer communication options are not used.", target)
	}

	if config.PeerTransportSecurity.CertFile == nil {
		return rule.FailedCheckResult("Option peer-transport-security.cert-file has not been set.", target)
	}
	if strings.TrimSpace(*config.PeerTransportSecurity.CertFile) == "" {
		return rule.FailedCheckResult("Option peer-transport-security.cert-file is empty.", target)
	}

	return rule.PassedCheckResult("Option peer-transport-security.cert-file set to allowed value.", target)
}
