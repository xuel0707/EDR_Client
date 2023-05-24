get_mem()
{
	pid=`cat /var/run/antiapt.pid`
	vm=`grep VmSize /proc/$pid/status | awk '{print $2}'`
	rss=`grep VmRSS /proc/$pid/status | awk '{print $2}'`
	eval $1=$vm
	eval $2=$rss
}

show_fd()
{
	pid=`cat /var/run/antiapt.pid`
	ls -l /proc/$pid/fd
}
