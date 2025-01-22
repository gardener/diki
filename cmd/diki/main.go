// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log"

	controllerruntime "sigs.k8s.io/controller-runtime"

	"github.com/gardener/diki/cmd/diki/app"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/provider/builder"
	"github.com/gardener/diki/pkg/provider/garden"
	"github.com/gardener/diki/pkg/provider/gardener"
	"github.com/gardener/diki/pkg/provider/managedk8s"
	"github.com/gardener/diki/pkg/provider/virtualgarden"
)

func main() {
	cmd := app.NewDikiCommand(
		map[string]provider.ProviderOption{
			garden.ProviderID:        {ProviderFromConfigFunc: builder.GardenProviderFromConfig, MetadataFunc: builder.GardenProviderMetadata},
			gardener.ProviderID:      {ProviderFromConfigFunc: builder.GardenerProviderFromConfig, MetadataFunc: builder.GardenerProviderMetadata},
			managedk8s.ProviderID:    {ProviderFromConfigFunc: builder.ManagedK8SProviderFromConfig, MetadataFunc: builder.ManagedK8SProviderMetadata},
			virtualgarden.ProviderID: {ProviderFromConfigFunc: builder.VirtualGardenProviderFromConfig, MetadataFunc: builder.VirtualGardenProviderMetadata},
		},
	)

	if err := cmd.ExecuteContext(controllerruntime.SetupSignalHandler()); err != nil {
		log.Fatal(err)
	}
}
