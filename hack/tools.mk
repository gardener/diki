# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

TAILWINDCSS                := $(TOOLS_BIN_DIR)/tailwindcss

# default tool versions
TAILWINDCSS_VERSION ?= v3.3.3

#########################################
# Tools                                 #
#########################################
$(TAILWINDCSS): $(call tool_version_file,$(TAILWINDCSS),$(TAILWINDCSS_VERSION))
	curl -L -o $(TAILWINDCSS) https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWINDCSS_VERSION)/tailwindcss-$(shell uname -s | tr '[:upper:]' '[:lower:]' | sed 's/darwin/macos/')-$(shell uname -m | sed 's/x86_64/x64/')
	chmod +x $(TAILWINDCSS)

# Override typos target from gardener's tools.mk which incorrectly
# references $(GARDENER_HACK_DIR)/tools/ instead of $(GARDENER_TOOL_DIR)/.
$(TYPOS): $(call tool_version_file,$(TYPOS),$(TYPOS_VERSION))
	@TYPOS_VERSION=$(TYPOS_VERSION) bash $(GARDENER_TOOL_DIR)/install-typos.sh
