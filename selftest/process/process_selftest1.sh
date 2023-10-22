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
. ./test_webexec.sh
. ./test_tunnel.sh
. ./test_danger.sh
. ./test_abnormal.sh
. ./test_blacklist.sh

# 打开进程日志调试开关，查看事件日志
touch /tmp/process.df

#下面的测试用普通用户权限做
myid=`id -u`
if [ $myid -eq 0 ]; then
	echo "NOT do this test by root"
	exit
fi

get_mem vm1 rss1

test_webexec_prepare #此处仅准备，测试在process_selftest2.sh里做

test_abnormal       #先做abnormal test，使得在清理之前有足够的时间上传样本
test_reverseshell   #先做reverseshell test，缩短检测时间
test_tunnel         #先做tunnel test，使得在清理之前有足够的时间做阻断
test_miner
test_danger         #test_danger里产生test_badelf，给test_privilege用
test_privilege
test_mbr
test_caidao
test_blacklist

#给一点时间让sniper结束非法进程
if [ $event_kill -ne 0 ]; then
	test_privilege_wait_stop
	test_reverseshell_wait_stop
fi

echo
echo "== Stop test commands =="

test_miner_clean
test_reverseshell_clean
test_privilege_clean
test_mbr_clean
test_caidao_clean
test_tunnel_clean
test_danger_clean
test_abnormal_clean
test_blacklist_clean

get_mem vm2 rss2
echo "Sniper Memory before test: VmSize $vm1, VmRSS $rss1"
echo "Sniper Memory  after test: VmSize $vm2, VmRSS $rss2"

test_privilege_exp_shell
