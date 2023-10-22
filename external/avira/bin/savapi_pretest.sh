#!/usr/bin/env bash
set -e
#
# Copyright (c) 2022 Avira Operations GmbH & Co. KG
#
# Description: Used for the PRETEST action of Updater
# VERSION=1.0.0.9
#

################################################################################
# Set and check the input parameters
#   * $1 - The path to the installation directory
################################################################################
PRETEST_INSTALL_DIR="$1"
if [ -z "${PRETEST_INSTALL_DIR}" ]
then
     echo "[SAVAPI_ERROR] The input parameters were not specified"
     exit 1
fi

################################################################################
# Set the internal variables needed for the PRETEST action
################################################################################
#
# NOTE:
#   By default, all PRETEST files are supposed to be in the PRETEST directory.
#   In cases when SAVAPI modules are spread over multiple directories, the
#   following variables must be modified. If the update process is called with
#   "--install-module-path" option, then a corresponding environment variable 
#   will be set with the name: <module_name>+"_MODULE_PRETEST_DIR"

# The path to directory containing the engine files
if [ -z "${AVE2_MODULE_PRETEST_DIR}" ]
then
     AVE2_MODULE_PRETEST_DIR="${PRETEST_INSTALL_DIR}";
fi

# The path to directory containing the VDF files
if [ -z "${VDF_MODULE_PRETEST_DIR}" ]
then
     VDF_MODULE_PRETEST_DIR="${PRETEST_INSTALL_DIR}";
fi

# The path to directory containing the SAVAPI binary files
SAVAPI_DIR_PATH="${PRETEST_INSTALL_DIR}"

################################################################################
# Run the PRETEST action for SAVAPI using the specified directory
################################################################################
if [ -x "${SAVAPI_DIR_PATH}/savapi" ]
then
    "${SAVAPI_DIR_PATH}/savapi" --pretest "--ave-dir=${AVE2_MODULE_PRETEST_DIR}" "--vdf-dir=${VDF_MODULE_PRETEST_DIR}" "--ldpath=${SAVAPI_DIR_PATH}"
else
    echo "[SAVAPI_WARNING] The SAVAPI binary file '${SAVAPI_DIR_PATH}/savapi' couldn't be accessed. The PRETEST action is skipped!"
fi
