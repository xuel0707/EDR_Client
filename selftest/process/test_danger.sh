test_danger()
{
	echo "== Danger Test =="

	#事件
	cc -o badelf badelf.c
	./badelf test_badelf
	echo exit | ./test_badelf

	myid=`id -u`
	if [ $myid -eq 0 ]; then
		echo "NOT do danger command test by root"
		return
	fi

	/bin/rm /        2>/dev/null
	/bin/rm /etc     2>/dev/null
	/bin/rm /usr     2>/dev/null
	/bin/rm /dev     2>/dev/null
	/bin/rm /boot    2>/dev/null
	/bin/rm /home    2>/dev/null
	/bin/rm /root    2>/dev/null

	#非事件

}

test_danger_clean()
{
	echo "== Danger Test Clean =="

}
