#!/usr/bin/env bash
set -e
#
# Copyright (c) 2022 Avira Operations GmbH & Co. KG
#
# VERSION=1.0.0.9
# Description: Collects informations used by the POST step script.
#              It will be run as a PRE action for each of the following
#              modules: AVE2, VDF or SAVAPI.
#

################################################################################
# Set and check the input parameters
#   * $1 - The process identifier of the parent process (i.e. the PID of the
#          Updater binary)
#   * $2 - The path to the installation directory
#   * $3 - The mode of the script: 'reload' or 'restart'
#   * $4 - The module to be reloaded (for $3=reload only)
################################################################################
PARENT_PID="$1"
INSTALL_DIR="$2"
SCRIPT_MODE="$3"
MODULE="$4"
if [ -z "${PARENT_PID}" -o -z "${SCRIPT_MODE}" -o -z "${INSTALL_DIR}" ]
then
     echo "[SAVAPI_ERROR] The input parameters were not specified"
     exit 1
fi

################################################################################
# Append the SCRIPT_MODE in the post-utils file
################################################################################
POST_UTILS_FILEPATH="${INSTALL_DIR}/savapi_post_utils.$PARENT_PID"
echo "${SCRIPT_MODE} ${MODULE}" >> "${POST_UTILS_FILEPATH}"
