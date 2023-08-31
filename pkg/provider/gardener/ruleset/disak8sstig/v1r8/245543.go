// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r8

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	kubeutils "github.com/gardener/diki/pkg/kubernetes/utils"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/gardener/internal/utils"
	"github.com/gardener/diki/pkg/rule"
)

var _ rule.Rule = &Rule245543{}

type Rule245543 struct {
	Client    client.Client
	Namespace string
	Options   *Options245543
	Logger    *slog.Logger
}

type Options245543 struct {
	AcceptedTokens []struct {
		User   string `yaml:"user"`
		UID    string `yaml:"uid"`
		Groups string `yaml:"groups"`
	}
}

func (r *Rule245543) ID() string {
	return ID245543
}

func (r *Rule245543) Name() string {
	return "Kubernetes API Server must disable token authentication to protect information in transit (MEDIUM 245543)"
}

func (r *Rule245543) Run(ctx context.Context) (rule.RuleResult, error) {
	const (
		kapiName = "kube-apiserver"
		option   = "token-auth-file"
	)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      kapiName,
			Namespace: r.Namespace,
		},
	}

	target := gardener.NewTarget("cluster", "seed", "kind", "deployment", "name", kapiName, "namespace", r.Namespace)

	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(deployment), deployment); err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	optSlice, err := utils.GetCommandOptionFromDeployment(ctx, r.Client, kapiName, kapiName, r.Namespace, option)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	if r.Options == nil {
		if len(optSlice) == 0 {
			return rule.SingleCheckResult(r, rule.PassedCheckResult(fmt.Sprintf("Option %s has not been set.", option), target)), nil
		}

		return rule.SingleCheckResult(r, rule.FailedCheckResult(fmt.Sprintf("Option %s is set.", option), target)), nil
	}

	if len(optSlice) > 1 {
		return rule.SingleCheckResult(r, rule.WarningCheckResult(fmt.Sprintf("Option %s has been set more than once in container command.", option), target)), nil
	}

	optionByteSlice, err := kubeutils.GetVolumeConfigByteSliceByMountPath(ctx, r.Client, deployment, kapiName, optSlice[0])
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult(err.Error(), target)), nil
	}

	optionString := string(optionByteSlice)
	optionStringArray := strings.Split(optionString, "\n")
	tokens := make([][]string, 0, len(optionStringArray))
	for _, optionStringLine := range optionStringArray {
		token := strings.SplitN(optionStringLine, ",", 4)
		token[0] = "***"

		if len(token) < 3 {
			return rule.SingleCheckResult(r, rule.FailedCheckResult("Invalid token.", target)), nil
		}

		// we append an empty string in the end,
		// because isTokenAccepted expects 4 element array
		if len(token) == 3 {
			token = append(token, "")
		}

		// we strip " if present in both ends,
		// because isTokenAccepted does not expect them
		trimedGroups := strings.TrimSpace(token[3])
		if len(trimedGroups) >= 2 && trimedGroups[0] == '"' && trimedGroups[len(trimedGroups)-1] == '"' {
			token[3] = trimedGroups[1 : len(trimedGroups)-1]
		}
		tokens = append(tokens, token)
	}

	for _, token := range tokens {
		if !r.isTokenAccepted([4]string(token)) {
			return rule.SingleCheckResult(r, rule.FailedCheckResult("Invalid token.", target)), nil
		}
	}

	return rule.SingleCheckResult(r, rule.AcceptedCheckResult("All defined tokens are accepted.", target)), nil
}

func (r *Rule245543) isTokenAccepted(token [4]string) bool {
	for _, acceptedToken := range r.Options.AcceptedTokens {
		if token[1] == acceptedToken.User && token[2] == acceptedToken.UID && token[3] == acceptedToken.Groups {
			return true
		}
	}

	return false
}
