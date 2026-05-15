// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	controllerruntime "sigs.k8s.io/controller-runtime"

	"github.com/gardener/diki/cmd/diki/app"
	"github.com/gardener/diki/pkg/config/merge"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/provider/builder"
	"github.com/gardener/diki/pkg/provider/garden"
	gardenmerge "github.com/gardener/diki/pkg/provider/garden/ruleset/securityhardenedshoot"
	"github.com/gardener/diki/pkg/provider/gardener"
	gardenermerge "github.com/gardener/diki/pkg/provider/gardener/ruleset/disak8sstig"
	"github.com/gardener/diki/pkg/provider/managedk8s"
	managedk8sdisa "github.com/gardener/diki/pkg/provider/managedk8s/ruleset/disak8sstig"
	"github.com/gardener/diki/pkg/provider/managedk8s/ruleset/securityhardenedk8s"
	"github.com/gardener/diki/pkg/provider/virtualgarden"
	virtualgardenmerge "github.com/gardener/diki/pkg/provider/virtualgarden/ruleset/disak8sstig"
)

func main() {
	cmd := app.NewDikiCommand(
		map[string]provider.ProviderOption{
			garden.ProviderID:        {ProviderFromConfigFunc: builder.GardenProviderFromConfig, MetadataFunc: builder.GardenProviderMetadata, ValidateConfigFunc: garden.ValidateProviderConfig, MergeRegistryFunc: gardenmerge.RegisterMergeFuncs},
			gardener.ProviderID:      {ProviderFromConfigFunc: builder.GardenerProviderFromConfig, MetadataFunc: builder.GardenerProviderMetadata, ValidateConfigFunc: gardener.ValidateProviderConfig, MergeRegistryFunc: gardenermerge.RegisterMergeFuncs},
			managedk8s.ProviderID:    {ProviderFromConfigFunc: builder.ManagedK8SProviderFromConfig, MetadataFunc: builder.ManagedK8SProviderMetadata, DefaultDikiConfigFunc: managedk8s.ManagedK8sDefaultDikiConfigFunc, ValidateConfigFunc: managedk8s.ValidateProviderConfig, MergeRegistryFunc: managedk8sMergeRegistryFunc},
			virtualgarden.ProviderID: {ProviderFromConfigFunc: builder.VirtualGardenProviderFromConfig, MetadataFunc: builder.VirtualGardenProviderMetadata, ValidateConfigFunc: virtualgarden.ValidateProviderConfig, MergeRegistryFunc: virtualgardenmerge.RegisterMergeFuncs},
		},
	)

	if err := cmd.ExecuteContext(controllerruntime.SetupSignalHandler()); err != nil {
		log.Fatal(err)
	}
}

func managedk8sMergeRegistryFunc(r *merge.Registry) {
	managedk8sdisa.RegisterMergeFuncs(r)
	securityhardenedk8s.RegisterMergeFuncs(r)
}
