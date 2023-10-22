#!/bin/bash

#zx process selftest 2021.10

#导入测试脚本
. ./check_process_policy.sh
. ./stop_cmd.sh
. ./mem_fd.sh

. ./test_miner.sh
. ./test_reverseshell.sh
. ./test_privilege.sh
. ./test_mbr.sh
. ./test_caidao.sh
. ./test_tunnel.sh
. ./test_danger.sh
. ./test_abnormal.sh
. ./test_webexec.sh

#下面的测试需要root权限做
myid=`id -u`
if [ $myid -ne 0 ]
then
	echo "Please do this test by root"
	exit
fi

#test_privilege_prepare

get_mem vm1 rss1

test_miner_root
test_mbr_root
test_tunnel_root
test_abnormal_root
test_webexec_root

test_miner_clean
test_mbr_clean
test_tunnel_clean
test_abnormal_clean
test_webexec_clean

get_mem vm2 rss2
echo "Sniper Memory before test: VmSize $vm1, VmRSS $rss1"
echo "Sniper Memory  after test: VmSize $vm2, VmRSS $rss2"
