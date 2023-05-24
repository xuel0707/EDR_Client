stopcmd_quite()
{
	cmdpid=`ps -eaf | grep "$*" | grep -v grep | awk '{print $2}'`
	if [ "$cmdpid" != "" ]; then
		kill -9 $cmdpid
		if [ $? -ne 0 ]; then
			echo "Error: stopcmd_quite $* fail"
			echo
		fi
	fi
}

stopcmd()
{
	cmdpid=`ps -eaf | grep "$*" | grep -v grep | awk '{print $2}'`
	if [ "$cmdpid" != "" ]; then
		kill -9 $cmdpid
		if [ $? -ne 0 ]; then
			echo "Error: stopcmd $* fail"
			echo
		fi

		if [ "$study" = "" -a "$operation" = "" -a $event_kill -ne 0 ]; then
			echo "Error: $* running, terminate policy fails"
			echo
		fi
	else
		if [ "$study" != "" -o "$operation" != "" -o $event_kill -eq 0 ]; then
			echo "Error: $* not running, make sure not terminated by policy"
			echo
		fi
	fi
}
