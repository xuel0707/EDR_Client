test_tunnel()
{
	echo
	echo "== Tunnel Test =="

	mkfifo /tmp/tunnel_fifo

	#事件
	#nc
	echo ">> nc"
	cat /tmp/tunnel_fifo | nc localhost 11111 2>/dev/null | nc -l 11112 >/tmp/tunnel_fifo &
# 等1秒，以免拼管道命令时，把下面的命令也拼上了
# TODO pipe inode会复用，因此不仅根据pipe inode拼，还要考虑pipe的时间，或其他特征
sleep 1
	nc -l 11113 0</tmp/tunnel_fifo | nc 1.2.3.4 11114 >/tmp/tunnel_fifo 2>/dev/null &
sleep 1
	netcat -l -p 11115 0</tmp/tunnel_fifo | netcat -l -p 11116 | tee /tmp/tunnel_fifo &

	#rinetd
	if [ ! -x /usr/sbin/rinetd ]; then
		echo "Warning: skip rinetd test, no /usr/sbin/rinetd"
	else
		echo ">> rinetd"
		/usr/sbin/rinetd
	fi

	#socat
	echo ">> socat"
	nohup socat -d TCP4-LISTEN:11121,reuseaddr,fork TCP4:1.2.3.4:11122 2>/dev/null &
	nohup socat -T 600 UDP4-LISTEN:11123,reuseaddr,fork UDP4:1.2.3.4:11124 2>/dev/null &
	nohup socat -d -d -d tcp-l:11125,reuseaddr,bind=0.0.0.0,fork tcp-l:11126,bind=0.0.0.0,reuseaddr,retry=10 2>/dev/null &
	nohup socat -d -d -d -v tcp:1.2.3.4:11127,forever,intervall=10,fork tcp:localhost:11128 2>/dev/null &

	#非事件
	socat --help >/dev/null 2>&1
}

test_tunnel_root()
{
	echo
	echo "== Tunnel Test =="

	#事件
	#iptables
	echo ">> iptables"
	iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j DNAT --to 127.0.0.1:8080
	iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport 80 -j DNAT --to 127.0.0.1:8080 2>/dev/null

	iptables -t nat -A PREROUTING -d 192.167.5.51 -p tcp --dport 22 -j DNAT --to 192.167.5.111:22
	iptables -t nat -D PREROUTING -d 192.167.5.51 -p tcp --dport 22 -j DNAT --to 192.167.5.111:22 2>/dev/null

	echo ">> firewall-cmd"
	firewall-cmd --permanent --add-forward-port=port=3333:proto=tcp:toport=80:toaddr=192.167.7.200
	firewall-cmd --permanent --remove-forward-port=port=3333:proto=tcp:toport=80:toaddr=192.167.7.200 2>/dev/null

	#非事件
	firewall-cmd --permanent --add-port=3333/tcp
	firewall-cmd --permanent --remove-port=3333/tcp
}

test_tunnel_clean()
{
	echo "== Tunnel Test Clean =="

	rm -f /tmp/tunnel_fifo

	stopcmd_quite "cat /tmp/tunnel_fifo"
	stopcmd_quite "nc localhost 11111"
	stopcmd_quite "nc 1.2.3.4 11114"

	stopcmd "nc -l 1111"
	stopcmd "netcat -l -p 1111"
	stopcmd "rinetd"
	stopcmd "socat"
}
