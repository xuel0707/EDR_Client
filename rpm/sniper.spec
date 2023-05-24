Summary: Sniper主机安全与管理系统
Name: snipercli
Version: 5.1.02.1128
Release: 1
License: Proprietary
Vendor: 上海高重信息科技有限公司
Group: Applications/System
Source: sniper-linux.tar.gz

%description
Sniper主机安全与管理系统

%prep
%setup -c

%build
cd sniper-linux
make

%install
cd sniper-linux
install -d %{buildroot}/sbin/
install -d %{buildroot}/etc/cron.d/
install -d %{buildroot}/etc/xdg/autostart/
install -d %{buildroot}/opt/snipercli/
install -m 755 ./dist/*                   %{buildroot}/opt/snipercli/
install -m 755 ./dist/sniper              %{buildroot}/sbin/
install -m 755 ./dist/assist_sniper       %{buildroot}/sbin/
install -m 755 ./dist/hydra               %{buildroot}/opt/snipercli/
install -m 755 ./dist/sniper_cron         %{buildroot}/etc/cron.d/
install -m 755 ./dist/snipertray.desktop  %{buildroot}/etc/xdg/autostart/
install -m 755 ./dist/sniper_location.db  %{buildroot}/opt/snipercli/
install -m 755 ./dist/webshell_detector   %{buildroot}/opt/snipercli/

%clean
rm -rf $RPM_BUILD_ROOT
rm -rf $RPM_BUILD_DIR/%{name}-%{version}


#from deb/sniper/DEBIAN/preinst
%pre

#停止服务
running=`ps -eaf | grep /sbin/sniper | grep -v grep`
if [ "$running" != "" ]
then
	echo "$running"
	/sbin/sniper -s ZH94f2JlcH19Tnx0 >/dev/null 2>&1
fi

plist=`ps -C snipertray -o pid=`
if [ "$plist" != "" ]
then
	echo "$plist" | xargs kill -9
fi

#删除V5版老文件
if [ -d /usr/share/antiapt/.mondb ]
then
	rm -rf /usr/share/antiapt/
fi

#预创建目录
mkdir -p /opt/snipercli/

exit 0


#from deb/sniper/DEBIAN/postinst
%post

LOCATION="/opt/snipercli"
KMOD_LOCATION="/lib/modules/`uname -r`/kernel/kernel/"
#ZX20200812 交叉编译时指定内核头文件目录 cross compiling，如在银河麒麟4.0.2sp2上为sp4编译
#对于rpm打包，仅是举银河麒麟做个例子，银河麒麟是deb包
#KMOD_LOCATION="/lib/modules/4.4.131-20200529.kylin.desktop-generic/kernel/kernel/"
LOG="/var/log/sniper-install.log"
OLDVERSION=`cat /var/run/antiapt.version 2>/dev/null`
CMD="sniper"
MOD="sniper_edr"

chown -R root:root ${LOCATION}
chown root:root /sbin/sniper
chown root:root /sbin/assist_sniper
chown root:root /opt/snipercli/hydra
chown root:root /etc/xdg/autostart/snipertray.desktop
chown root:root /opt/snipercli/sniper_location.db
chown root:root /opt/snipercli/webshell_detector

echo "======== AntiAPT EDR ========"
echo "==== `date` : `pwd` ====" >> $LOG

ppid=`grep PPid /proc/$$/status | awk '{print $2}'`
servinfo=`cat /proc/$ppid/cmdline | cut -s -f2 -d'(' | cut -s -f1 -d')'`
if [ "$servinfo" != "" ]
then
	server=`echo $servinfo | cut -s -f1 -d'_'`
	port=`echo $servinfo | cut -s -f2 -d'_' | cut -s -f1 -d'@'`
fi

validserver=0
check_server()
{
	if [ "$server" = "" ]
	then
		echo "No server argument"
		return
	fi
	if [ "$port" = "" ]
	then
		echo "No port argument"
		return
	fi

	tmpval=`echo $port | sed "s/[0-9]//g"`
	if [ "$tmpval" != "" ]
	then
        	echo "Invalid Port: [$port]"
		return
	fi
	if [ $port -lt 1 -o $port -gt 65535 ]
	then
        	echo "Invalid Port: [$port]"
		return
	fi

	tmpval=`echo $server | grep "[0-9a-zA-Z]"`
	if [ "$tmpval" = "" ]
	then
		echo "Invalid server: [$server]"
		return
	fi

	tmpval=`echo $server | sed "s/[0-9]//g"`
	if [ "$tmpval" != "..." ]
	then
		validserver=1
		return
	fi

        ip1=`echo $server | cut -f1 -d'.'`
        ip2=`echo $server | cut -f2 -d'.'`
        ip3=`echo $server | cut -f3 -d'.'`
        ip4=`echo $server | cut -f4 -d'.'`
        if [ "${ip1}" = "" -o "${ip2}" = "" -o "${ip3}" = "" -o "${ip4}" = "" ]
        then
                echo "Invalid IP: [$server]"
		return
        fi
        if [ ${ip1} -eq 0 -o ${ip1} -ge 255 -o ${ip2} -gt 255 -o ${ip3} -gt 255 -o ${ip4} -eq 0 -o ${ip4} -ge 255 ]
        then
                echo "Invalid IP: [$server]"
		return
        fi

	validserver=1
}

check_server
if [ $validserver -eq 1 ]
then
	echo "$server:$port" > /etc/sniper.conf
	echo "Server is $server, port is $port, run sniper in network mode"
else
	echo "Run sniper in local mode"
	echo "Turn to network mode by command /opt/snipercli/sniper_servaddr later"
fi

set_env_for_qt()
{
	# 不是在图形界面里做的安装，不用起qt程序
	if [ "$DISPLAY" = "" ]
	then
		return
	fi

	# 正确显示中文
	export LANG=zh_CN.UTF-8

	# 找登录用户的进程
	loginuser=`ls -lL /proc/self/fd/0 | awk '{print $3}'`
	if [ "$loginuser" = "" ]
	then
		return
	fi

	# root用户不用重设环境变量
	if [ "$loginuser" = "root" ]
	then
		return
	fi

	ppid=`cat /proc/$$/status | grep PPid | awk '{print $2}'`
	while [ 1 ]
	do
		if [ $ppid -le 2 ]
		then
			return
		fi

		username=`ls -l /proc/$ppid/status | awk '{print $3}'`
		if [ "$username" = "" ]
		then
			return
		fi

		if [ "$username" = "$loginuser" ]
		then
			break
		fi

		PID=$ppid
		ppid=`cat /proc/$PID/status | grep PPid | awk '{print $2}'`
	done

	# 取登录用户的环境变量
	#dbusaddress=`cat /proc/$ppid/environ | tr "\0" "\n" | grep "^DBUS_SESSION_BUS_ADDRESS=" | cut -s -f2- -d'='`
	#  sessionid=`cat /proc/$ppid/environ | tr "\0" "\n" | grep "^GNOME_DESKTOP_SESSION_ID=" | cut -s -f2- -d'='`
	#    homedir=`cat /proc/$ppid/environ | tr "\0" "\n" | grep "^HOME=" | cut -s -f2- -d'='`

	#if [ "$dbusaddress" = "" ]
	#then
	#	return
	#fi
	#export HOME=$homedir
	#export DBUS_SESSION_BUS_ADDRESS=$dbusaddress
	#export GNOME_DESKTOP_SESSION_ID=$sessionid

	# 通过安装时起的托盘程序做卸载可能失败，不确定是哪个环境变量影响，完全复制
	cat /proc/$ppid/environ | tr "\0" "\n" > /tmp/myenv.$ppid
	while [ 1 ]
	do
		read line
		if [ "$line" = "" ]
		then
			break
		fi
		export $line 2>/dev/null
	done < /tmp/myenv.$ppid
	rm -f /tmp/myenv.$ppid

	# 正确显示中文。防止之前重设环境变量改变LANG，这里再设一次
	export LANG=zh_CN.UTF-8
}

start_snipertray()
{
	# 不是在图形界面里做的安装，不用起托盘程序
	if [ "$DISPLAY" = "" ]
	then
		return
	fi

	if [ ! -f /opt/snipercli/snipertray ]
	then
		echo "no sniper tray program"
		return
	fi

	echo "start sniper tray"
	if [ "$loginuser" = "root" -o "$loginuser" = "" ]
	then
		/opt/snipercli/snipertray >/dev/null 2>/tmp/snipertray.log &
	else
		/opt/snipercli/snipertray $loginuser >/dev/null 2>/tmp/snipertray.log &
	fi
	grep -v ocale /tmp/snipertray.log 2>/dev/null | grep -v "^$"
	cat /tmp/snipertray.log >> $LOG 2>/dev/null

	sleep 1
	plist=`ps -C snipertray -o pid=`
	if [ "$plist" != "" ]
	then
		echo "sniper tray started"
		echo "sniper tray started" >> $LOG
	else
		echo "sniper tray fail"
		echo "sniper tray fail" >> $LOG
	fi
}

set_env_for_qt

ulimit -c unlimited

if [ ! -x /etc/rc.d/rc.local ]
then
	mkdir -p /etc/rc.d
	touch /etc/rc.d/rc.local
	chmod +x /etc/rc.d/rc.local
fi
if [ ! -x /etc/rc.local ]
then
	touch /etc/rc.local
	chmod +x /etc/rc.local
fi

myid=`id -u`
if [ "$myid" != "0" ]
then
	echo "Install FAIL! Permission denied"
	echo "Install FAIL! Permission denied" >> $LOG
	exit 1
fi

mkdir -p ${LOCATION}
if [ ! -d ${LOCATION} ]
then
	echo "Install FAIL! can't create directory ${LOCATION}"
	echo "Install FAIL! can't create directory ${LOCATION}" >> $LOG
	exit 1
fi

mkdir -p ${KMOD_LOCATION}
if [ ! -d ${KMOD_LOCATION} ]
then
	echo "Install FAIL! can't create directory ${KMOD_LOCATION}"
	echo "Install FAIL! can't create directory ${KMOD_LOCATION}" >> $LOG
	exit 1
fi
cp -f /opt/snipercli/${MOD}.ko ${KMOD_LOCATION}
chown root:root ${KMOD_LOCATION}/${MOD}.ko

show_release()
{
	if [ -f /etc/neokylin-release ]
	then
		osrelease=`cat /etc/neokylin-release`
		if [ "$osrelease" != "" ]
		then
			echo "OS: $osrelease"
			return
		fi
	fi

	if [ -f /etc/system-release ]
	then
		osrelease=`cat /etc/system-release`
		if [ "$osrelease" != "" ]
		then
			echo "OS: $osrelease"
			return
		fi
	fi

	if [ -f /etc/centos-release ]
	then
		osrelease=`cat /etc/centos-release`
		if [ "$osrelease" != "" ]
		then
			echo "OS: $osrelease"
			return
		fi
	fi

	if [ -f /etc/redhat-release ]
	then
		osrelease=`cat /etc/redhat-release`
		if [ "$osrelease" != "" ]
		then
			echo "OS: $osrelease"
			return
		fi
	fi

	if [ -f /etc/lsb-release ]
	then
		osrelease=`grep DISTRIB_DESCRIPTION /etc/lsb-release | cut -s -f2 -d'='`
		if [ "$osrelease" != "" ]
		then
			echo "OS: $osrelease"
			return
		fi
	fi

	if [ -f /etc/os-release ]
	then
		osrelease=`grep PRETTY_NAME /etc/os-release | cut -s -f2 -d'='`
		if [ "$osrelease" != "" ]
		then
			echo "OS: $osrelease"
			return
		fi
	fi
}

# show distribution release
show_release

echo "Prepare module sniper_edr. may need some minutes ..."
/sbin/depmod -a > /dev/null 2>&1
echo "Module ok"


# if app not autostart, set autostart
CMD="/sbin/sniper >/dev/null 2>&1 &"
auto_sniper()
{
	grep \<sniper\> $1 > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		# check if there is a "exit 0" at end (like ubuntu)
		grep -r "^[[:space:]]*exit 0" $1 >/dev/null 2>&1
		if [ $? -ne 0 ]
		then
			# append to the end
			echo ${CMD} >> $1
		else
			# insert before "exit 0"
			sed -i "/^[[:space:]]*exit[[:space:]]*0/i ${CMD}" $1
		fi
	fi
	BASH_HEADER=`grep "^#\!" $1 2>/dev/null`
	if [ "$BASH_HEADER" = "" ]
	then
		sed -i "1i\#\!\/bin\/bash" $1
	fi
}
auto_sniper /etc/rc.d/rc.local
auto_sniper /etc/rc.local

CMD="/sbin/assist_sniper >/dev/null 2>&1 &"
auto_assist_sniper()
{
	grep \<assist_sniper\> $1 > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		# check if there is a "exit 0" at end (like ubuntu)
		grep -r "^[[:space:]]*exit 0" $1 >/dev/null 2>&1
		if [ $? -ne 0 ]
		then
			# append to the end
			echo ${CMD} >> $1
		else
			# insert before "exit 0"
			sed -i "/^[[:space:]]*exit[[:space:]]*0/i ${CMD}" $1
		fi
	fi
	BASH_HEADER=`grep "^#\!" $1 2>/dev/null`
	if [ "$BASH_HEADER" = "" ]
	then
		sed -i "1i\#\!\/bin\/bash" $1
	fi
}
auto_assist_sniper /etc/rc.d/rc.local
auto_assist_sniper /etc/rc.local

echo "Start sniper"
cd /
chmod +x /sbin/sniper
chmod +x /sbin/assist_sniper
chmod +x /opt/snipercli/hydra
/sbin/sniper >/dev/null 2>&1 &
/sbin/assist_sniper >/dev/null 2>&1 &

#遇到过等1秒没antiapt.pid，但事实上sniper起来的情况，故多等一会儿
i=0
while [ 1 ]
do
        if [ $i -eq 5 ]; then break; fi
        i=`expr $i + 1`

        sleep 1
        if [ ! -f /var/run/antiapt.pid ]; then continue; fi
done

if [ ! -f /var/run/antiapt.pid ]; then
    echo "Run sniper fail"
    echo "Run sniper fail" >> $LOG
    echo "Sniper install FAIL" >> $LOG
    exit 1
fi

PID=`cat /var/run/antiapt.pid`
sniper_on=`ps -p $PID -o comm=`
if [ "$sniper_on" != "sniper" ]
then
	echo "antiapt.pid: `cat /var/run/antiapt.pid`" >> $LOG 2>&1
	echo "ps -p $PID -o comm=" >> $LOG
	ps -p $PID -o comm= >> $LOG 2>&1
	echo "==1st==" >> $LOG

	/sbin/sniper >/dev/null 2>&1 &
	sleep 1
	PID=`cat /var/run/antiapt.pid`
	sniper_on=`ps -p $PID -o comm=`
	if [ "$sniper_on" != "sniper" ]
	then
		echo "antiapt.pid: `cat /var/run/antiapt.pid`" >> $LOG 2>&1
		echo "ps -p $PID -o comm=" >> $LOG
		ps -p $PID -o comm= >> $LOG 2>&1
		echo "==2nd==" >> $LOG

		echo "Run sniper fail"
		echo "Sniper install FAIL" 
		echo "Run sniper fail" >> $LOG
		echo "Sniper install FAIL" >> $LOG

		/sbin/sniper -s ZH94f2JlcH19Tnx0 >/dev/null 2>&1

		MOD=`lsmod | grep -w sniper_edr`
		if [ "$MOD" != "" ]
		then
			rmmod sniper_edr >/dev/null 2>&1
		fi

		rm -f /etc/cron.d/sniper_cron >/dev/null 2>&1
		echo "rm /etc/cron.d/sniper_cron" >> $LOG

		exit 1
	fi
fi

NEWVERSION=`cat /var/run/antiapt.version 2>/dev/null`

chown root:root /etc/cron.d/sniper_cron >/dev/null 2>&1
chmod 644 /etc/cron.d/sniper_cron >/dev/null 2>&1
chmod 755 /opt/snipercli/sniper_chk >/dev/null 2>&1
chmod 755 /opt/snipercli/assist_sniper_chk >/dev/null 2>&1
chmod 755 /opt/snipercli/hydra >/dev/null 2>&1
chmod 755 /opt/snipercli/static >/dev/null 2>&1

echo "== Sniper ${NEWVERSION} installed =="
echo "== Sniper ${NEWVERSION} installed ==" >> $LOG

# 起托盘程序
start_snipertray

# 模块没起来，不算安装失败 TODO 由sniper报告模块未加载日志
MOD=`lsmod | grep -w sniper_edr`
if [ "$MOD" = "" ]
then
	sleep 1
	MOD=`lsmod | grep -w sniper_edr`
fi
if [ "$MOD" != "" ]
then
	echo
	echo "Check sniper runtime state ..."
        # 等待一会儿，检查sniper运行状态
        for((i=0;i<30;i++))
        do
                grep "sniper start" /var/run/antiapt.status >/dev/null 2>&1
                if [ $? -eq 0 ]
                then
                	sleep 1
                        break
                fi
                sleep 1
                echo -n "."
        done
	/sbin/sniper -t
	exit 0
fi

echo "Warning: Load sniper_edr module fail"
echo "Warning: Load sniper_edr module fail" >> $LOG

echo
echo "Following logs may be helpful:"
echo "-- last 10 lines of /var/log/antiapt.log --"
tail -10 /var/log/antiapt.log
tail -10 /var/log/antiapt.log >> $LOG
echo

if [ -f /var/log/messages ]
then
	echo "-- last 5 lines of /var/log/messages --"
	tail -5 /var/log/messages
	tail -5 /var/log/messages >> $LOG
else
	echo "-- last 5 lines of /var/log/kern.log --"
	tail -5 /var/log/kern.log
	tail -5 /var/log/kern.log >> $LOG
fi

exit 0



#from deb/sniper/DEBIAN/prerm
%preun

#rpm -U Update安装时，流程是pre,post,preun,postun，
#令preun和postun啥也不做，否则会把更新后的包又删除了
ppid=`grep PPid /proc/$$/status | awk '{print $2}'`
cat /proc/$ppid/cmdline | tr "\0" "\n" | grep "^\-[a-zA-Z]*U" >/dev/null 2>&1
if [ $? -eq 0 ]
then
	exit 0
fi

#停止服务
/sbin/sniper --uninstall ZH94f2J1cH19Tnx0
running=`ps -eaf | grep /sbin/sniper | grep -v grep`
if [ "$running" != "" ]
then
        echo "stop running sniper fail"
        echo "$running"
        exit 1
fi

plist=`ps -C snipertray -o pid=`
if [ "$plist" != "" ]
then
        echo "$plist" | xargs kill -9
fi

exit 0


#from deb/sniper/DEBIAN/postrm
%postun

#rpm -U Update安装时，流程是pre,post,preun,postun，
#令preun和postun啥也不做，否则会把更新后的包又删除了
ppid=`grep PPid /proc/$$/status | awk '{print $2}'`
cat /proc/$ppid/cmdline | tr "\0" "\n" | grep "^\-[a-zA-Z]*U" >/dev/null 2>&1
if [ $? -eq 0 ]
then
	exit 0
fi

#删除残留数据
rm -rf /opt/snipercli/

KMOD_LOCATION="/lib/modules/`uname -r`/kernel/kernel/"
#ZX20200812 交叉编译时指定内核头文件目录 cross compiling，如在银河麒麟4.0.2sp2上为sp4编译
#对于rpm打包，仅是举银河麒麟做个例子，银河麒麟是deb包
#KMOD_LOCATION="/lib/modules/4.4.131-20200529.kylin.desktop-generic/kernel/kernel/"
rm -f ${KMOD_LOCATION}/sniper_edr.ko

sed -i "/sniper/d" /etc/rc.local 2>/dev/null
sed -i "/sniper/d" /etc/rc.d/rc.local 2>/dev/null

exit 0


%files
%defattr (-,root,root)
/sbin/sniper
/sbin/assist_sniper
/etc/cron.d/sniper_cron
/etc/xdg/autostart/snipertray.desktop
/opt/snipercli/

%changelog
