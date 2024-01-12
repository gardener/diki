// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1r11

import (
	shareddisastig "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig"
	sharedv1r11 "github.com/gardener/diki/pkg/shared/ruleset/disak8sstig/v1r11"
)

const (
	ID242376    = "242376"
	ID242377    = "242377"
	ID242378    = "242378"
	ID242379    = "242379"
	ID242380    = "242380"
	ID242381    = "242381"
	ID242382    = "242382"
	ID242383    = "242383"
	ID242384    = "242384"
	ID242385    = "242385"
	ID242386    = "242386"
	ID242387    = "242387"
	ID242388    = "242388"
	ID242389    = "242389"
	ID242390    = "242390"
	ID242391    = "242391"
	ID242392    = "242392"
	ID242393    = "242393"
	ID242394    = "242394"
	ID242395    = "242395"
	ID242396    = "242396"
	ID242397    = "242397"
	ID242398    = "242398"
	ID242399    = "242399"
	ID242400    = "242400"
	ID242402    = "242402"
	ID242403    = "242403"
	ID242404    = "242404"
	ID242405    = "242405"
	ID242406    = "242406"
	ID242407    = "242407"
	ID242408    = "242408"
	ID242409    = "242409"
	ID242410    = "242410"
	ID242411    = "242411"
	ID242412    = "242412"
	ID242413    = "242413"
	ID242414    = "242414"
	ID242415    = "242415"
	ID242417    = "242417"
	ID242418    = "242418"
	ID242419    = "242419"
	ID242420    = "242420"
	ID242421    = "242421"
	ID242422    = "242422"
	ID242423    = "242423"
	ID242424    = "242424"
	ID242425    = "242425"
	ID242426    = "242426"
	ID242427    = "242427"
	ID242428    = "242428"
	ID242429    = "242429"
	ID242430    = "242430"
	ID242431    = "242431"
	ID242432    = "242432"
	ID242433    = "242433"
	ID242434    = "242434"
	ID242436    = "242436"
	ID242437    = "242437"
	ID242438    = "242438"
	ID242442    = "242442"
	ID242443    = "242443"
	ID242444    = "242444"
	ID242445    = "242445"
	ID242446    = "242446"
	ID242447    = "242447"
	ID242448    = "242448"
	ID242449    = "242449"
	ID242450    = "242450"
	ID242451    = "242451"
	ID242452    = "242452"
	ID242453    = "242453"
	ID242454    = "242454"
	ID242455    = "242455"
	ID242456    = "242456"
	ID242457    = "242457"
	ID242459    = "242459"
	ID242460    = "242460"
	ID242461    = "242461"
	ID242462    = "242462"
	ID242463    = "242463"
	ID242464    = "242464"
	ID242465    = "242465"
	ID242466    = "242466"
	ID242467    = "242467"
	ID245541    = "245541"
	ID245542    = "245542"
	ID245543    = "245543"
	ID245544    = "245544"
	ID254800    = "254800"
	ID254801    = "254801"
	IDNodeFiles = "node-files"
	IDPodFiles  = "pod-files"
)

type RuleOption interface {
	Options242414 | Options242415 | sharedv1r11.Options245543 | sharedv1r11.Options254800 | shareddisastig.OptionsFiles
}
