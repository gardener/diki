// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/kubernetes/config"
	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule242428{}

type Rule242428 struct {
	Client    client.Client
	Namespace string
	Logger    *slog.Logger
}

func (r *Rule242428) ID() string {
	return ID242428
}

func (r *Rule242428) Name() string {
	return "Kubernetes etcd must have a certificate for communication (MEDIUM 242428)"
}

func (r *Rule242428) Run(ctx context.Context) (rule.RuleResult, error) {
	checkResults := []rule.CheckResult{}

	checkResults = append(checkResults, r.checkStatefulSet(ctx, "etcd-main"))
	checkResults = append(checkResults, r.checkStatefulSet(ctx, "etcd-events"))

	return rule.RuleResult{
		RuleID:       r.ID(),
		RuleName:     r.Name(),
		CheckResults: checkResults,
	}, nil
}

func (r *Rule242428) checkStatefulSet(ctx context.Context, statefulSetName string) rule.CheckResult {
	statefulSet := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      statefulSetName,
			Namespace: r.Namespace,
		},
	}

	target := gardener.NewTarget("cluster", "seed", "name", statefulSetName, "namespace", r.Namespace, "kind", "statefulSet")

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

	if config.ClientTransportSecurity.CertFile == nil {
		return rule.FailedCheckResult("Option client-transport-security.cert-file has not been set.", target)
	}
	if strings.TrimSpace(*config.ClientTransportSecurity.CertFile) == "" {
		return rule.FailedCheckResult("Option client-transport-security.cert-file is empty.", target)
	}

	return rule.PassedCheckResult("Option client-transport-security.cert-file set to allowed value.", target)
}
