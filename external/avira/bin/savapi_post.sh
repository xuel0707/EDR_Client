#!/usr/bin/env bash
#
# Copyright (c) 2022 Avira Operations GmbH & Co. KG
#
# VERSION=1.0.0.13
# Description: Restarts or reloads SAVAPI. Used by the AVupdater in the POST action

################################################################################
# Set and check the input parameters
#   * $1 - The process identifier of the parent process (i.e. the PID of the
#          Updater binary)
#   * $2 - The path to the installation directory
################################################################################
PARENT_PID="$1"
INSTALL_DIR="$2"
if [ -z "${PARENT_PID}" -o -z "${INSTALL_DIR}" ]
then
     echo "[SAVAPI_ERROR] The input parameters were not specified"
     exit 1
fi

################################################################################
# Set script internal variables
#   * SAVAPI_FILEPATH - path to the SAVAPI binary file
#   * POST_UTILS_FILEPATH - path to the post-utils file (created by the
#    savapi_pre.sh script)
################################################################################
POST_UTILS_FILEPATH="${INSTALL_DIR}/savapi_post_utils.$PARENT_PID"
# NOTE:
#   By default, all POST files are supposed to be in the installation directory.
#   In cases when SAVAPI modules are spread over multiple directories, the
#   following variables must be modified.

################################################################################
# Set the paths to SAVAPI modules
################################################################################

# The path to directory containing the SAVAPI binary files
if [ -z "${SAVAPI3_MODULE_INSTALL_DIR}" ]
then
    SAVAPI3_MODULE_INSTALL_DIR="${INSTALL_DIR}"
fi

# The path to directory containing the AVE2 files
if [ -z "${AVE2_MODULE_INSTALL_DIR}" ]
then
     AVE2_MODULE_INSTALL_DIR="${INSTALL_DIR}"
fi

# The path to directory containing the VDF files
if [ -z "${VDF_MODULE_INSTALL_DIR}" ]
then
     VDF_MODULE_INSTALL_DIR="${INSTALL_DIR}"
fi

# The path to SAVAPI binary file
SAVAPI_FILEPATH="${SAVAPI3_MODULE_INSTALL_DIR}/savapi"

# No POST action will be run if the SAVAPI binary can't be executed
if [ ! -x "$SAVAPI_FILEPATH" ]
then
    echo "[SAVAPI_WARNING] The SAVAPI binary file '$SAVAPI_FILEPATH' couldn't be accessed. The POST action is skipped!"
    rm -f "${POST_UTILS_FILEPATH}"
    exit 0
fi

################################################################################
# Determine which action (reload or restart) SAVAPI processes should do
################################################################################
SAVAPI_ACTION="restart"
if [ ! -f "${POST_UTILS_FILEPATH}" ]
then
    echo "[SAVAPI_WARNING] PRE action wasn't run. Choosing default SAVAPI action (${SAVAPI_ACTION})"
else
    if grep "restart" "${POST_UTILS_FILEPATH}" > /dev/null
    then
        SAVAPI_ACTION="restart"
    elif grep "reload" "${POST_UTILS_FILEPATH}" > /dev/null
    then
        SAVAPI_ACTION="reload"
        
        # check the module that needs to be reloaded
        grep "reload AVE2" "${POST_UTILS_FILEPATH}" &>/dev/null && SAVAPI_ACTION="${SAVAPI_ACTION}_AVE2"        
        grep "reload VDF" "${POST_UTILS_FILEPATH}" &>/dev/null && SAVAPI_ACTION="${SAVAPI_ACTION}_VDF"        
    fi
fi

# Remove the post-utils file
rm -f "${POST_UTILS_FILEPATH}"

################################################################################
# Get all running SAVAPI processes started from the given install directory
# and apply the POST action (restart or engine-reload) against every process
################################################################################
SAVAPI_REPORT=`"${SAVAPI_FILEPATH}" --report 2>&1`
if [ $? -ne 0 ]
then
    # NOTE: This may happen on the systems where the shared resources (i.e. semaphores) limit is too low.
    #       Example: On *BSDs, the semaphores system limit is set to 10, by default.
    echo "[SAVAPI_WARNING] '${SAVAPI_FILEPATH} --report' failed (${SAVAPI_REPORT}). The POST action is skipped!"
    exit 0
fi

# For the rest of the script, exit immediately if a command returns a non-zero status
set -e

# Go through all the pids and choose and apply restart/reload for each
SAVAPI_PIDS=`echo "${SAVAPI_REPORT}" | grep "CMDLINE" | cut -d']' -f1 | cut -d'[' -f2`
for SAVAPI_PID in ${SAVAPI_PIDS}
do
    # Get the startup cmdline of the process
    SAVAPI_CMDLINE=`echo "${SAVAPI_REPORT}" | grep ${SAVAPI_PID} | grep "CMDLINE: " | cut -d':' -f2- | cut -d' ' -f2-`

    # Get the real SAVAPI start mode
    MODE="restart"
    if [ "reload" = "${SAVAPI_ACTION:0:6}" ]
    then
        # NOTE: reload is performed only if "duplicate_modules" option is activated
        DUPLICATE_MODULES=`echo "${SAVAPI_REPORT}" | grep ${SAVAPI_PID} | grep "DUPLICATE_MODULES: " | cut -d':' -f2-`
        if [ $DUPLICATE_MODULES -eq 1 ]
        then
            # add "--reload-engine" for a SAVAPI reload
            SAVAPI_CMDLINE="$SAVAPI_CMDLINE --reload-engine"
            MODE="reload"
        fi
    fi

    # NOTE: remove the ' "-N"' from the command line in order not to block the console when executing the command
    SAVAPI_CMDLINE=`echo $SAVAPI_CMDLINE | sed 's/\ \"\-N\"//g'`

    # Check if the running instance needs to be updated or not
    UPDATE_INSTANCE=1
    if [ "restart" != "${SAVAPI_ACTION}" ]
    then
	    # Set the paths to the AVE and VDF used by the running SAVAPI instance
	    INSTANCE_AVE2_MODULE_INSTALL_DIR=`echo "${SAVAPI_REPORT}" | grep ${SAVAPI_PID} | grep "AVE_PATH: " | cut -d':' -f2- | cut -d' ' -f2-`
	    INSTANCE_VDF_MODULE_INSTALL_DIR=`echo "${SAVAPI_REPORT}" | grep ${SAVAPI_PID} | grep "VDF_PATH: " | cut -d':' -f2- | cut -d' ' -f2-`
	    
        # Check if the instance uses the expected paths
	    if [ "reload_AVE2" = "${SAVAPI_ACTION}" -a ! "${INSTANCE_AVE2_MODULE_INSTALL_DIR}" -ef "${AVE2_MODULE_INSTALL_DIR}" ] 
	    then
	        UPDATE_INSTANCE=0
	    elif [ "reload_VDF" = "${SAVAPI_ACTION}" -a ! "${INSTANCE_VDF_MODULE_INSTALL_DIR}" -ef "${VDF_MODULE_INSTALL_DIR}" ]
	    then
	        UPDATE_INSTANCE=0
	    else
	        if [ ! "${INSTANCE_AVE2_MODULE_INSTALL_DIR}" -ef "${AVE2_MODULE_INSTALL_DIR}" -a ! "${INSTANCE_VDF_MODULE_INSTALL_DIR}" -ef "${VDF_MODULE_INSTALL_DIR}" ]
	        then
	            UPDATE_INSTANCE=0
	        fi
	    fi
	    
	    # For older SAVAPI versions (i.e. '--report' does not return the AVE2 and VDF paths), always update the instance
        if [ -z "${INSTANCE_AVE2_MODULE_INSTALL_DIR}" -a -z "${INSTANCE_VDF_MODULE_INSTALL_DIR}" ]
        then
            UPDATE_INSTANCE=1
        fi
	fi
        
    # Execute SAVAPI reload/restart
    if [ $UPDATE_INSTANCE -eq 1 ]
    then
        echo "[SAVAPI_INFO] R${MODE:1}ing SAVAPI ($SAVAPI_PID: $SAVAPI_CMDLINE)"
        eval "$SAVAPI_CMDLINE"
    fi
done

# Return success if the script reaches the end
exit 0
