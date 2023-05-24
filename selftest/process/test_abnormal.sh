test_abnormal()
{
	echo "== Abnormal Test =="

	#事件
	cp /bin/ls /tmp/ls1
	cp /bin/ls /var//tmp/ls2
	cp /bin/ls /dev/shm/ls3

	/tmp/ls1 /tmp/ls1
	/var/tmp/ls2 /var/tmp/ls2 #用于配置过滤
	/dev/shm/ls3 /dev/shm/ls3 #用于配置可信

	#非事件
}

test_abnormal_root()
{
	echo "== Abnormal Test =="

	#事件
	cp /bin/ls /var/log/ls4
	/var/log/ls4 /var/log/ls4

	#非事件
}

test_abnormal_clean()
{
	echo "== Abnormal Test Clean =="

	rm -f /tmp/ls1 /var/tmp/ls2 /dev/shm/ls3 /var/log/ls4

}
