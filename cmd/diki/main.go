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
)

func main() {
	cmd := app.NewDikiCommand(map[string]provider.ProviderFromConfigFunc{
		"garden":        builder.GardenProviderFromConfig,
		"gardener":      builder.GardenerProviderFromConfig,
		"managedk8s":    builder.ManagedK8SProviderFromConfig,
		"virtualgarden": builder.VirtualGardenProviderFromConfig,
	})

	if err := cmd.ExecuteContext(controllerruntime.SetupSignalHandler()); err != nil {
		log.Fatal(err)
	}
}
