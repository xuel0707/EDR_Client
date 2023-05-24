test_privilege()
{
	echo
	echo "== Privilege Escalation Test =="

	#事件
	old_dirtycow_stopflag=`stat /tmp/dirtycow_routine_stopped 2>/dev/null | grep Change`

	echo ">> privilege event1: dirtyc0w"
	gcc -pthread dirtyc0w.c -o dirtyc0w
	nohup ./dirtyc0w /tmp/foo m00000000000000000 &

	echo ">> privilege event2: pokemon"
	gcc -pthread pokemon.c -o pokemon
	nohup ./pokemon /tmp/foo n00000000000000001 &

	#非事件，有提权关键日志
	echo ">> privilege keylog1: SUID Privilege access file"
	passwd --help > /dev/null

	echo ">> privilege keylog2: SUID Privilege run command"
	type su >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		echo "su -c whoami"
		su -c "whoami;cp test_badelf exp;chmod +s exp"
	fi

	type sudo >/dev/null 2>&1
	if [ $? -eq 0 ]; then
		echo "sudo whoami"
		sudo "whoami;cp test_badelf exp;chmod +s exp"
	fi
}

test_privilege_clean()
{
	echo "== Privilege Escalation Test Clean =="
	stopcmd "dirtyc0w"
	stopcmd "pokemon"
}

test_privilege_wait_stop()
{
	i=0
	while [ 1 ]
	do
		new_dirtycow_stopflag=`stat /tmp/dirtycow_routine_stopped 2>/dev/null | grep Change`
		if [ "$new_dirtycow_stopflag" != "$old_dirtycow_stopflag" ]; then
			break
		fi

		echo "wait 1s for dirtycow routine stopped"
		sleep 1

		i=`expr $i + 1`
		if [ $i -ge 30 ]; then
			echo "total wait 30s for dirtycow routine stopped, fail"
			break
		fi
	done
}

test_privilege_exp_shell()
{
	echo "exp shell. "
	md5sum exp
	echo "note1: exp should be danger-trust"
	echo
	echo "note2: exit bash 5s later, if bash living"
	./exp
}
