#!/usr/bin/bash
. "$(dirname $(readlink -f "$0"))/runlib"
RUN_VULKAN "$@"
