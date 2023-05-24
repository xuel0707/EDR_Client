event_on=0
event_kill=0
event_locking=0

check_policy()
{
	key_on=`grep "$2:开启" /opt/snipercli/protect.lst.file 2>/dev/null`
	eval $1_on="$key_on"

	if [ "$key_on" != "" ]; then
		event_on=`expr $event_on + 1`

		key_kill=`echo "$key_on" | grep "阻断:开启"`
		eval $1_kill="$key_kill"

		if [ "$key_kill" != "" ]; then
			event_kill=`expr $event_kill + 1`

			key_locking=`echo "$key_on" | grep "锁定:开启"`
			eval $1_kill="$key_locking"

			if [ "$key_locking" != "" ]; then
				event_locking=`expr $event_locking + 1`
			fi
		fi
	fi

}

check_policy miner        "挖矿行为"
check_policy reverseshell "反弹shell"
check_policy privilege    "非法提权"
check_policy mbr          "MBR防护"
check_policy caidao       "中国菜刀命令执行"
check_policy webexec      "对外服务进程异常执行"
check_policy tunnel       "隧道搭建"
check_policy danger       "危险命令"
check_policy abnormal     "异常进程"
check_policy normal       "进程行为采集"

prule_linenum=`grep -m 1 -n "^进程:" /opt/snipercli/rule.info | cut -f1 -d:`
frule_linenum=`grep -m 1 -n "^文件:" /opt/snipercli/rule.info | cut -f1 -d:`
prule_count=`expr $frule_linenum - $prule_linenum - 1`

study=`grep "客户端模式.*学习" /opt/snipercli/conf.info`
operation=`grep "客户端模式.*运维" /opt/snipercli/conf.info`

if [ "$normal_on" != "" ]; then
	event_on=`expr $event_on - 1`
fi
#学习模式下监控哪些事件由管控定
if [ "$study" = "" -a $event_on -ne 0 -a $event_on -ne 9 ]; then
	echo "有事件没监控，请重新设置策略"
	exit
fi
if [ $event_kill -ne 0 -a $event_kill -ne 9 ]; then
	echo "有事件没阻断，请重新设置策略"
	exit
fi

#if [ "$study" != "" -a $prule_count -eq 0 ]; then
#	echo "当前测试模式为学习模式，请设置黑进程规则"
#	exit
#fi
if [ "$operation" != "" ]; then
	if [ "$normal_on" = "" -o $event_on -eq 0 -o $event_kill -eq 0 -o $prule_count -eq 0 ]; then
		echo "当前测试模式为运维模式，请设置采集进程日志，监测并阻断所有事件，及黑进程规则"
		exit
	fi
fi

#已经不在rule.info里记录矿池，所以这个检查屏蔽
#myminepool=`grep zxtestpool.com /opt/snipercli/rule.info`
#if [ "$myminepool" = "" ]; then
#	echo "没有设置自定义矿池域名zxtestpool.com"
#	exit
#fi

echo "模式1：无采集，无监测， 无阻断， 无规则  ---- 无日志，无事件"
echo "模式2：有采集，无监测， 无阻断， 无规则  ---- 有一般进程和命令行审计日志，无事件"
echo "模式3：无采集，all监测，无阻断， 无规则  ---- all事件"
echo "模式4：无采集，all监测，all阻断，无规则  ---- all事件，all阻断，锁ip"
echo "模式5：无采集，all监测，all阻断，有规则  ---- 有事件，有阻断，锁ip；有违规事件并阻断；过滤进程无日志，但对黑名单无效；可信进程不阻断有日志"
echo "模式6：无采集，无监测， 无阻断， 有规则  ---- 有违规事件"
echo "模式7：学习模式，有规则                  ---- 有事件，无阻断，查看事件日志的进程树是否完整"
echo "模式8：运维模式，有采集，all阻断，有规则 ---- 有事件，无阻断"
echo
echo

if [ "$study" != "" ]; then
	echo "当前测试模式7：学习模式，有规则                  ---- 有事件，无阻断，查看事件日志的进程树是否完整"
elif [ "$operation" != "" ]; then
	echo "当前测试模式8：运维模式，有采集，all阻断，有规则 ---- 有事件，无阻断"
elif [ "$normal_on" = "" -a $event_on -eq 0 -a $prule_count -eq 0 ]; then
	echo "当前测试模式1：无采集，无监测， 无阻断， 无规则  ---- 无日志，无事件"
elif [ "$normal_on" != "" -a $event_on -eq 0 -a $prule_count -eq 0 ]; then
	echo "当前测试模式2：有采集，无监测， 无阻断， 无规则  ---- 有一般进程和命令行审计日志，无事件" 
elif [ "$normal_on" = "" -a $event_on -ne 0 -a $event_kill -eq 0 -a $prule_count -eq 0 ]; then
	echo "当前测试模式3：无采集，有监测， 无阻断， 无规则  ---- all事件"
elif [ "$normal_on" = "" -a $event_on -ne 0 -a $event_kill -ne 0 -a $prule_count -eq 0 ]; then
	echo "当前测试模式4：无采集，all监测，all阻断，无规则  ---- all事件，all阻断，锁ip"
elif [ "$normal_on" = "" -a $event_on -ne 0 -a $event_kill -ne 0 -a $prule_count -ne 0 ]; then
	echo "当前测试模式5：无采集，all监测，all阻断，有规则  ---- 有事件，有阻断，锁ip；有违规事件并阻断；过滤进程无日志，但对黑名单无效；可信进程不阻断有日志"
elif [ "$normal_on" = "" -a $event_on -eq 0 -a $event_kill -eq 0 -a $prule_count -ne 0 ]; then
	echo "当前测试模式6：无采集，无监测， 无阻断， 有规则  ---- 有违规事件"
elif [ "$normal_on" != "" -a $event_on -ne 0 -a $event_kill -eq 0 -a $prule_count -eq 0 ]; then
	echo "当前测试模式7：有采集，all监测，无阻断， 无规则  ---- 查看事件日志的进程树是否完整，模拟学习策略"
else
	if [ $prule_count -ne 0 ]; then
		echo "其他测试模式：$normal_on，监测事件数量$event_on，阻断事件数量$event_kill，有规则"
	else
		echo "其他测试模式：$normal_on，监测事件数量$event_on，阻断事件数量$event_kill，无规则"
	fi
fi

echo
echo
