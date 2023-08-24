// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"

	"github.com/gardener/diki/cmd/diki/app"
	"github.com/gardener/diki/pkg/provider"
	"github.com/gardener/diki/pkg/provider/builder"
)

func main() {
	cmd := app.NewDikiCommand(context.Background(), map[string]provider.ProviderFromConfigFunc{
		"gardener": builder.GardenerProviderFromConfig,
	})

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
