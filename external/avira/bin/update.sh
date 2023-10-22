#!/usr/bin/env bash
#
# Copyright (c) 2022 Avira Operations GmbH & Co. KG
#
# VERSION=1.0.0.8
# Description: Contains the basic update commands for SAVAPI Server and Library
#

#
# SAVAPI Server update
#
# product update (all modules)
./avupdate.bin --config=avupdate-savapi-product.conf --check-product

# engine update (engine binaries and virus definition modules)
# ./avupdate.bin --config=avupdate-savapi-engine.conf --check-product

#
# SAVAPI Library update
#
# product update (all modules)
#./avupdate.bin --config=avupdate-savapilib-product.conf --check-product

# engine update (engine binaries and virus definition modules)
#./avupdate.bin --config=avupdate-savapilib-engine.conf --check-product

