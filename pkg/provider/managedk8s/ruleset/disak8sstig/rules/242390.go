package rules

import (
	"context"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/diki/pkg/rule"

	sharedrules "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/rules"
)

var _ rule.Rule = &Rule242390{}

type Rule242390 struct {
	InstanceID   string
	Client       client.Client
	V1RESTClient rest.Interface
}

func (r *Rule242390) ID() string {
	return sharedrules.ID242390
}

func (r *Rule242390) Name() string {
	return "The Kubernetes API server must have anonymous authentication disabled (HIGH 242390)"
}

func (r *Rule242390) Run(ctx context.Context) (rule.RuleResult, error) {

	//retrieve URL to the kube-api server which is guarded

	//parse HttpResponse from the Get(url)

}
