# SPDX-FileCopyrightText: Copyright Contributors to the Gardener project
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
