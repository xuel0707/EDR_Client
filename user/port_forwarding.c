#include "header.h"

//TODO nginx端口转发
/*
 * ssh 
 * [-L [bind_address:]port:host:hostport]
 * [-R [bind_address:]port:host:hostport]
 * [-D [bind_address:]port]
 * 
 * ssh -fNgL 7001:localhost:389 LdapServerHost
 * ssh -fNR 7001:localhost:389 LdapClientHost
 * ssh -D 7001 <SSH Server>
 */

/*
 * iptabels 
 * iptables -t nat -A PREROUTING -d 192.168.88.134 -p tcp --dport 80 -j DNAT --to 192.168.88.134:8080
 * iptables -t nat -A PREROUTING -p tcp -i eth0 --dport 31521 -j DNAT --to 192.168.2.65:152
 *
 * /sbin/iptables是个链接，真实执行的可能是
 * /sbin/iptables-x.x.x或/sbin/iptables-multi或/sbin/xtables-multi
 */
 
/*
 * nc 
 * nc -l 222 0</tmp/fifo | nc 192.168.207.133 22 > /tmp/fifo
 * nc 192.168.207.133 22 0</tmp/fifo | nc -l 222 > /tmp/fifo
 * nc -lu 2001
 */

/* rinetd */

/*
 * mkfifo /tmp/fifo 或 mknod /tmp/fifo p
 * listener-to-client 转发：nc -l [localport] 0</tmp/fifo | nc [target ip] [port] | tee /tmp/fifo
 * listener-to-listener 转发：nc -l [localport] 0</tmp/fifo | nc -l [localport2] | tee /tmp/fifo [没成功，不明白]
 * client-to-client 转发：nc [ip1] [port1] 0</tmp/fifo | nc [ip2] [port2] | tee /tmp/fifo [没成功，不明白]
 *
 * echo nc [ip] [port] > relay.sh; chmod +x relay.sh; nc -l -p [port2] -e relay.sh
 *
 * cat /tmp/fifo | nc localhost 23 | nc -l 9000 > /tmp/fifo 登录本机9000端口相当于登录23端口
 *
 * 下面两条命令等价
 * nc -l 222 0</tmp/fifo | nc 192.168.207.133 22 > /tmp/fifo
 * nc 192.168.207.133 22 0</tmp/fifo | nc -l 222 > /tmp/fifo
 * 
 * ncat --sh-exec "ncat 192.168.172.131 80" -l 9876  --keep-open
 * cat /tmp/fifo | nc localhost 8000 | nc -l 9000 > /tmp/fifo
 *
 * netcat -l -p 81 0 < /tmp/fifo | netcat -l -p 80 | tee /tmp/fifo
 */

/*
 * portmap -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port
 * portmap -m 2 -p1 6666 -h2 公网IP -p2 7777
 * portmap -m 3 -h1 127.0.0.1 -p1 22 -h2 公网ip -p2 6666
 */

/*
 * portfwd [-h] [add | delete | list | flush] [args]
 * portfwd add –l 3389 –p 3389 –r 172.16.194.191
 */

/*
 * tcpfwd|udpfwd <local_addr:local_port> <dest_addr:dest_port> [-d] [-o]
 * tcpfwd 0.0.0.0:1022 192.168.1.77:22
 * tcpfwd :::1022 192.168.1.77:22
 * tcpfwd 0.0.0.0:80 2001:db8:3::2:80
 */

/*
 * socat -d -d -d tcp-l:80,reuseaddr,bind=0.0.0.0,fork tcp-l:8080,bind=0.0.0.0,reuseaddr,retry=10
 * socat -d -d -d -v tcp:vpsip:8080,forever,intervall=10,fork tcp:localhost:80
 */

/*
 * ptunnel -x password
 * ptunnel -p proxy-address -lp listen-port -da destination-address -dp destination-port
 * 例如，
 * 攻击机：10.91.214.179
 * 跳板机：10.91.214.180 允许攻击机访问
 *   靶机：10.91.214.183 允许跳板机访问，不允许攻击机访问
 * 跳板机上起服务器：ptunnel -x 1234
 * 攻击机上起客户端：ptunnel -p 10.91.214.180 -lp 2019 -da 10.91.214.183 -dp 22
 * 攻击机上ssh -p 2019 localhost，访问本机的2019端口，即访问到靶机的22端口
 *
 * ptunnel-ng是的Ptunnel的bug修复和重构版本
 * ptunnel-ng -p202.198.67.254 -l2222 -r192.168.30.23 -R22
 *
 * TODO
 * 攻击机的行为通常是无法监控的，只能监控跳板机的行为。ptunnel是走icmp协议，跳板机应该是没有一进一出的固定连接特征的
 * ptunnel基于ICMP echo(ping request)和reply(ping reply)实现隧道，将请求编码存在于ICMP数据内，与DNS隧道原理类似
 * ICMP tunnel的流量特征明显，它把非法流量隐藏在echo-request及echo-reply数据包的payload中，使数据包的内容及长度都发生改变
 * 不同操作系统默认的paylod长度及内容都不一样，但是都是固定的，比如Windows操作系统的ping包默认pyaload长度为32，内容为“abcdefghijklmnopqrstuvwabcdefghi”，
 * Linux系统payload默认长度为48，固定的Hex格式内容为“|0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637|”
 * 要禁止ICMP tunnel流量，首先可以通过限制echo-request及echo-reply包的长度，只允许长度为84（Linux）或长60（Windows）的echo-request或echo-reply
 * 更严格一点，还可以限制数据包的内容，例如使用iptables的string模块
 * -A INPUT -p icmp -m icmp --icmp-type 0 -m length --length 84 -m string --hex-string "|0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637|" --algo bm --to 65535 -j ACCEPT
 * -A INPUT -p icmp -m icmp --icmp-type 0 -m length --length 60 -m string --string "abcdefghijklmnopqrstuvwabcdefghi" --algo bm --to 65535 -j ACCEPT
 * -A INPUT -p icmp -m icmp --icmp-type 8 -m length --length 84 -m string --hex-string "|0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637|" --algo bm --to 65535 -j ACCEPT
 * -A INPUT -p icmp -m icmp --icmp-type 8 -m length --length 60 -m string --string "abcdefghijklmnopqrstuvwabcdefghi" --algo bm --to 65535 -j ACCEPT
 * -A INPUT -p icmp -m icmp --icmp-type 8 -j DROP
 * -A INPUT -p icmp -m icmp --icmp-type 0 -j DROP
 * -A OUTPUT -p icmp -m icmp --icmp-type 0 -m length --length 84 -m string --hex-string "|0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637|" --algo bm --to 65535 -j ACCEPT
 * -A OUTPUT -p icmp -m icmp --icmp-type 0 -m length --length 60 -m string --string "abcdefghijklmnopqrstuvwabcdefghi" --algo bm --to 65535 -j ACCEPT
 * -A OUTPUT -p icmp -m icmp --icmp-type 8 -m length --length 84 -m string --hex-string "|0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637|" --algo bm --to 65535 -j ACCEPT
 * -A OUTPUT -p icmp -m icmp --icmp-type 8 -m length --length 60 -m string --string "abcdefghijklmnopqrstuvwabcdefghi" --algo bm --to 65535 -j ACCEPT
 * -A OUTPUT -p icmp -m icmp --icmp-type 8 -j DROP
 * -A OUTPUT -p icmp -m icmp --icmp-type 0 -j DROP
 */

/* 检测方法：查命令参数是否带了2个端口 */
static int is_socat_port_forward(char *cmdline)
{
	char *ptr = NULL;
	int port = 0, ret = 0;

	if (cmdline) {
		ptr = strrchr(cmdline, ':');
	}
	if (!ptr) {
		return 0;
	}

	/* 取最后一个参数里的端口号 */
	ret = sscanf(ptr, ":%d", &port);
	if (ret != 1 || port <= 0) {
		return 0;
	}

	port = 0;
	while (ptr != cmdline) {
		/* 回退到最后一个参数的头部 */
		if (*ptr != ' ') {
			ptr--;
			continue;
		}

		/* 回退到倒数第二个参数的端口处 */
		while (ptr != cmdline) {
			if (*ptr == ':') {
				/* 取最后一个参数里的端口号 */
				ret = sscanf(ptr, ":%d", &port);
				if (ret != 1 || port <= 0) {
					return 0;
				}
				return 1;
			}
			ptr--;
		}
		return 0;
	}
	return 0;
}

static int check_nc_option(char *str)
{
	char *ptr = NULL, *opt = NULL, *arg = NULL;
	char buf[S_LINELEN] = {0};

	if (!str) {
		return 0;
	}

	snprintf(buf, S_LINELEN, "%s", str);
	/* 拷贝一个nc命令行 */
	ptr = strchr(buf, '|');
	if (ptr) {
		*ptr = 0;
	}

	/* 查找是否带-l选项，考虑-vl，-lv的情况 */
	arg = buf;
	while ((opt = strstr(arg, " -"))) {
		/* 取一个参数 */
		ptr = strchr(opt+2, ' ');
		if (!ptr) { //这是最后一个参数
			if (strchr(opt, 'l')) {
				return 1;
			}
			return 0;
		}

		*ptr = 0;
		if (strchr(opt, 'l')) {
			return 1;
		}

		arg = ptr++;
	}
	return 0;
}

//TODO 这种用法需要查网络连接状态 echo nc [ip] [port] > relay.sh; chmod +x relay.sh; nc -l -p [port2] -e relay.sh
/* 检测方法：查命令参数是否带了2个nc命令 */
/* 检查nc是否带-l命令选项，排除nc x.x.x.x nnnn | bash | nc x.x.x.x mmmm的误报 */
static int is_nc_port_forward(char *cmdline)
{
	int len = 0, listen = 0;
	char *ptr = NULL, *str = NULL;

	if (cmdline) {
		ptr = strstr(cmdline, "nc ");
		len = 2;
		if (!ptr) {
			ptr = strstr(cmdline, "ncat ");
			len = 4;
			if (!ptr) {
				ptr = strstr(cmdline, "netcat ");
				len = 6;
			}
		}
	}
	if (!ptr) {
		return 0;
	}
	str = ptr + len;
	listen = check_nc_option(str);

	ptr = strstr(str, "nc ");
	len = 2;
	if (!ptr) {
		ptr = strstr(str, "ncat ");
		len = 4;
		if (!ptr) {
			ptr = strstr(str, "netcat ");
			len = 6;
			if (!ptr) {
				return 0;
			}
		}
	}
	str = ptr + len;
	listen += check_nc_option(str);

	if (listen) {
		return 1;
	}
	return 0;
}

/* ex. ssh -D 7001 host */
static int ssh_dynamic_port_forward(char *cmdline)
{
	int ret = 0, port = 0;
	char *ptr = NULL, address[64] = {0};

	if (cmdline) {
		ptr = strstr(cmdline, "D ");
	}
	if (ptr) {
		ret = sscanf(ptr, "D %63[^:]:%d %*s", address, &port);
		if (ret == 2 && port != 0) {
			return 1;
		}
		ret = sscanf(ptr, "D :%d %*s", &port);
		if (ret == 1 && port != 0) {
			return 1;
		}
		ret = sscanf(ptr, "D %d %*s", &port);
		if (ret == 1 && port != 0) {
			return 1;
		}
	}
	return 0;
}
/* ex. ssh -fNgL 7001:localhost:389 host
 *     ssh -fNR 7001:localhost:389 host */
static int ssh_port_forward(char *cmdline, char *tag)
{
	int ret = 0, port = 0, hostport = 0;
	char *ptr = NULL, address[64] = {0}, host[64] = {0};

	if (cmdline) {
		ptr = strstr(cmdline, tag);
	}
	if (ptr) {
		ret = sscanf(ptr+2, "%63[^:]:%d:%63[^:]:%d %*s", address, &port, host, &hostport);
		if (ret == 4 && port != 0 && hostport != 0) {
			return 1;
		}
		ret = sscanf(ptr+2, ":%d:%63[^:]:%d %*s", &port, host, &hostport);
		if (ret == 3 && port != 0 && hostport != 0) {
			return 1;
		}
		ret = sscanf(ptr+2, "%d:%63[^:]:%d %*s", &port, host, &hostport);
		if (ret == 3 && port != 0 && hostport != 0) {
			return 1;
		}
	}
	return 0;
}

/* tcpfwd|udpfwd <local_addr:local_port> <dest_addr:dest_port> [-d] [-o] */

int is_port_forward(taskstat_t *taskstat, int to_report_task_exit)
{
	char *cmd = NULL, *cmdline = NULL, *cmdname = NULL;

#if 0
	if (!prule.port_forward_on || !taskstat) {
		return 0;
	}
#else
	if (!taskstat)
		return 0;
#endif

	cmd = taskstat->cmd;
	cmdline = taskstat->args;
	cmdname = safebasename(cmd);

	if (strcmp(cmdname, "ssh") == 0) {
		if (ssh_port_forward(cmdline, "L ") || 
		    ssh_port_forward(cmdline, "R ") ||
		    ssh_dynamic_port_forward(cmdline)) {
			return 1;
		}
		return 0;
	}

	if (strcmp(cmdname, "rinetd") == 0 && access("/etc/rinetd.conf", F_OK) == 0) {
		return 1;
	}

	if (strcmp(cmdname, "socat") == 0) {
		return is_socat_port_forward(cmdline);
	}

	/* portmap -m method [-h1 host1] -p1 port1 [-h2 host2] -p2 port */
	if (strcmp(cmdname, "portmap") == 0 && strstr(cmdline, "-p1") && strstr(cmdline, "-p2")) { 
		return 1;
	}

	/* portfwd [-h] [add | delete | list | flush] [args] */
	if (strcmp(cmdname, "portfwd") == 0 && strstr(cmdname, "add")) {
		return 1;
	}

	if (strcmp(cmdname, "tcpfwd") == 0 || strcmp(cmdname, "udpfwd") == 0) {
		/* 可以借用socat的检测方法，检查命令参数是否带了2个端口 */
		return is_socat_port_forward(cmdline);
	}

	if (strcmp(cmdname, "nc") == 0 || strcmp(cmdname, "ncat") == 0 || strcmp(cmdname, "netcat") == 0) {
		return is_nc_port_forward(cmdline);
	}

	if (strncmp(cmdname, "ptunnel", 7) == 0) {
		return 1;
	}

	return 0;
}
