package rules

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/gardener/diki/pkg/rule"
	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ rule.Rule = &Rule242390{}

type Rule242390 struct {
	InstanceID      string
	KAPIExternalURL string
}

func (r *Rule242390) ID() string {
	return sharedrules.ID242390
}

func (r *Rule242390) Name() string {
	return "The Kubernetes API server must have anonymous authentication disabled (HIGH 242390)"
}

func (r *Rule242390) Run(ctx context.Context) (rule.RuleResult, error) {
	transportConfiguration := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	externalClient := &http.Client{
		Transport: transportConfiguration,
	}

	httpResponse, err := externalClient.Get(r.KAPIExternalURL)
	if err != nil {
		return rule.SingleCheckResult(r, rule.ErroredCheckResult("failed http request"+err.Error(), rule.NewTarget())), nil
	}

	if httpResponse.StatusCode == http.StatusUnauthorized {
		return rule.SingleCheckResult(r, rule.FailedCheckResult("kube-apiserver has anonymous authentication enabled", rule.NewTarget())), nil
	} else if httpResponse.StatusCode == http.StatusForbidden {
		return rule.SingleCheckResult(r, rule.PassedCheckResult("kube-apiserver has anonymous authentication disabled", rule.NewTarget())), nil
	} else {
		return rule.SingleCheckResult(r, rule.WarningCheckResult("the anonymous authentication configurations on the kube-apiserver can not be determined", rule.NewTarget())), nil
	}
}
