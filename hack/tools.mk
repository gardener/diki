# SPDX-FileCopyrightText: Contributors to the Gardener project
#
# SPDX-License-Identifier: Apache-2.0

TAILWINDCSS                := $(TOOLS_BIN_DIR)/tailwindcss

# default tool versions
TAILWINDCSS_VERSION ?= v3.3.3

#########################################
# Tools                                 #
#########################################
$(TAILWINDCSS): $(call tool_version_file,$(TAILWINDCSS),$(TAILWINDCSS_VERSION))
	./hack/download-tailwindcss.sh $(TAILWINDCSS) $(TAILWINDCSS_VERSION)
