test_webexec_root()
{
	echo "== Webexec Test =="

	n=0
	while [ $n -ne 60 ]
	do
		ready=`grep php /proc/sys/sniper/process_strategy` #这个动作需要root权限
		if [ "$ready" != "" ]; then
			break
		fi
		echo "phpserver not ready, wait 1s"
		sleep 1
		n=`expr $n + 1`
	done

	#事件，做ifconfig
	curl --location --request POST 'http://192.168.58.128:8123/test.php' \
	--header 'Content-Type: application/x-www-form-urlencoded' \
	--data-urlencode 'x=eval(base64_decode('\''QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JG09Z2V0X21hZ2ljX3F1b3Rlc19ncGMoKTskcD0nL2Jpbi9zaCc7JHM9Jy9zYmluL2lmY29uZmlnJzskZD1kaXJuYW1lKCRfU0VSVkVSWyJTQ1JJUFRfRklMRU5BTUUiXSk7JGM9c3Vic3RyKCRkLDAsMSk9PSIvIj8iLWMgXCJ7JHN9XCIiOiIvYyBcInskc31cIiI7JHI9InskcH0geyRjfSI7JGFycmF5PWFycmF5KGFycmF5KCJwaXBlIiwiciIpLGFycmF5KCJwaXBlIiwidyIpLGFycmF5KCJwaXBlIiwidyIpKTskZnA9cHJvY19vcGVuKCRyLiIgMj4mMSIsJGFycmF5LCRwaXBlcyk7JHJldD1zdHJlYW1fZ2V0X2NvbnRlbnRzKCRwaXBlc1sxXSk7cHJvY19jbG9zZSgkZnApO3ByaW50ICRyZXQ7O2VjaG8oIlhAWSIpO2RpZSgpOw=='\''));'

	#非事件，做date
	curl --location --request POST 'http://192.168.58.128:8123/test.php' \
	--header 'Content-Type: application/x-www-form-urlencoded' \
	--data-urlencode 'x=eval(base64_decode('\''QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO0BzZXRfdGltZV9saW1pdCgwKTtpZihQSFBfVkVSU0lPTjwnNS4zLjAnKXtAc2V0X21hZ2ljX3F1b3Rlc19ydW50aW1lKDApO307ZWNobygiWEBZIik7JG09Z2V0X21hZ2ljX3F1b3Rlc19ncGMoKTskcD0nL2Jpbi9zaCc7JHM9Jy9iaW4vZGF0ZSc7JGQ9ZGlybmFtZSgkX1NFUlZFUlsiU0NSSVBUX0ZJTEVOQU1FIl0pOyRjPXN1YnN0cigkZCwwLDEpPT0iLyI/Ii1jIFwieyRzfVwiIjoiL2MgXCJ7JHN9XCIiOyRyPSJ7JHB9IHskY30iOyRhcnJheT1hcnJheShhcnJheSgicGlwZSIsInIiKSxhcnJheSgicGlwZSIsInciKSxhcnJheSgicGlwZSIsInciKSk7JGZwPXByb2Nfb3Blbigkci4iIDI+JjEiLCRhcnJheSwkcGlwZXMpOyRyZXQ9c3RyZWFtX2dldF9jb250ZW50cygkcGlwZXNbMV0pO3Byb2NfY2xvc2UoJGZwKTtwcmludCAkcmV0OztlY2hvKCJYQFkiKTtkaWUoKTs='\''));'

}

test_webexec_prepare()
{
	nohup php -S 192.168.58.128:8123 &
}

test_webexec_clean()
{
	echo "== Webexec Test Clean =="

	stopcmd_quite "php -S"
}
