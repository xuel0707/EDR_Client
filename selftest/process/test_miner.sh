test_miner()
{
	echo "== Miner Test =="

	#事件
	cmd=`type wget | awk '{print $3}'`
	cp -p $cmd ./
	echo "./wget ddpool.cn"
	./wget http://ddpool.cn -O /tmp/1.html -o /tmp/wget.log

	#非事件
	echo "dig xmrig.com"
	dig xmrig.com >/dev/null

	echo "wget ddpool.cn"
	wget http://ddpool.cn -O /tmp/1.html -o /tmp/wget.log
}

test_miner_root()
{
	echo "== Miner Test =="

	if [ "$miner_kill" = "" -o "$study" != "" -o "$operation" != "" ]; then
		count=3
	else
		count=100
	fi

	#事件
	cmd=`type ping | awk '{print $3}'`
	cp -p $cmd ./

	echo "./ping ddpool.cn"
	./ping -c $count ddpool.cn >/dev/null

	echo "./ping www.zxtestpool.com"
	./ping -c $count www.zxtestpool.com >/dev/null

	#非事件
	echo "ping ddpool.cn"
	ping -c $count ddpool.cn >/dev/null

	echo "ping www.zxtestpool.com"
	ping -c $count www.zxtestpool.com >/dev/null
}

test_miner_clean()
{
	echo "== Miner Test Clean =="

	rm -f ./wget ./ping
}
