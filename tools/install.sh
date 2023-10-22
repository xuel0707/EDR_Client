#!/bin/bash
# Sniper install script

PATH="$PATH:/sbin:/bin:/usr/sbin:/usr/bin"
LOCATION="/opt/snipercli"
KMOD_LOCATION="/lib/modules/`uname -r`/kernel/kernel/"
LOG="/var/log/sniper-install.log"
OLDVERSION=`cat /var/run/antiapt.version 2>/dev/null | tr -d '\r\n\0'`
CMD="sniper"
ASSIST_CMD="assist_sniper"
ANTIVIRUS_CMD="sniper_antivirus"
MOD="sniper_edr"
oldsku=`cat /etc/sniper-sku 2>/dev/null | tr -d '\r\n\0'`
os_arch=`uname -m`

#如果没有System.map文件，生成一个
SYSTEM_MAP="/boot/System.map-`uname -r`"
BAK_SYSTEM_MAP="$SYSTEM_MAP.`date +%s`"
if [ ! -f $SYSTEM_MAP ]
then
	#下面的cp应当总是失败的，如果成功，说明错误地进入了这里
	#但由于先备份了System.map文件，错误还可以挽回
	cp $SYSTEM_MAP $BAK_SYSTEM_MAP 2>/dev/null
	if [ $? -ne 0 ]
	then
		cat /proc/kallsyms > $SYSTEM_MAP
	fi
fi

display="$DISPLAY"
loginuid=0
set_env_for_qt()
{
	# 不是在图形界面里做的安装，不用起qt程序
	if [ "$display" = "" ]; then
		return
	fi

	# 正确显示中文
	export LANG=zh_CN.UTF-8

	# 找登录用户的进程
	loginuid=`ls -lLn /proc/self/fd/0 | awk '{print $3}'`
	if [ "$loginuid" = "" ]; then
		return
	fi

	# start_snipertray总是重设环境变量，因为之前可能做过restart_snipertray，设置不是当前用户的环境变量

	ppid=`cat /proc/$$/status | grep PPid | awk '{print $2}'`
	while [ 1 ]
	do
		if [ $ppid -le 2 ]; then
			return
		fi

		uid=`ls -ln /proc/$ppid/status | awk '{print $3}'`
		if [ "$uid" = "" ]; then
			return
		fi

		if [ "$uid" = "$loginuid" ]; then
			break
		fi

		PID=$ppid
		ppid=`cat /proc/$PID/status | grep PPid | awk '{print $2}'`
	done

	# 通过安装时起的托盘程序做卸载可能失败，不确定是哪个环境变量影响，完全复制
	cat /proc/$ppid/environ | tr "\0" "\n" > /tmp/myenv.$ppid
	while [ 1 ]
	do
		read line
		if [ "$line" = "" ]; then
			break
		fi
		export $line 2>/dev/null
	done < /tmp/myenv.$ppid
	rm -f /tmp/myenv.$ppid

	# 正确显示中文。防止之前重设环境变量改变LANG，这里再设一次
	export LANG=zh_CN.UTF-8

	# PATH环境变量上面修改了，拼上系统路径
	PATH="$PATH:/sbin:/bin:/usr/sbin:/usr/bin"
}

start_snipertray()
{
	# 不是在图形界面里做的安装，不用起托盘程序
	if [ "$display" = "" ]; then
		return
	fi

	if [ ! -f /opt/snipercli/snipertray ]; then
		echo "no sniper tray program"
		return
	fi

	DISPLAY=""
	set_env_for_qt

	echo "start sniper tray"
	/opt/snipercli/snipertray $loginuid >/dev/null 2>/tmp/snipertray.log &
	grep -v ocale /tmp/snipertray.log 2>/dev/null | grep -v "^$"
	cat /tmp/snipertray.log >> $LOG 2>/dev/null

	sleep 1
	plist=`ps -C snipertray -o pid=`
	if [ "$plist" != "" ]; then
		echo "sniper tray started"
		echo "sniper tray started" >> $LOG
	else
		echo "sniper tray fail"
		echo "sniper tray fail" >> $LOG
	fi
}

restart_snipertray()
{
	DISPLAY=""
	uid=$1
	while [ 1 ]
	do
		read line
		if [ "$line" = "" ]; then
			break
		fi
		export $line 2>/dev/null
	done < /tmp/snipertrayenv.$uid
	rm -f /tmp/snipertrayenv.$uid

	# PATH环境变量上面修改了，拼上系统路径
	PATH="$PATH:/sbin:/bin:/usr/sbin:/usr/bin"

	/opt/snipercli/snipertray $uid >/dev/null 2>/tmp/snipertray.log &
}

set_env_for_qt

ulimit -c unlimited

if [ ! -x /etc/rc.d/rc.local ]; then
	mkdir -p /etc/rc.d
	touch /etc/rc.d/rc.local
	chmod +x /etc/rc.d/rc.local
fi
if [ ! -x /etc/rc.local ]; then
	touch /etc/rc.local
	chmod +x /etc/rc.local
fi

Usage()
{
	echo "Install Usage:"
	echo "    $0"
	echo "    $0 IP:Port [installtoken]"
	echo "Uninstall Usage:"
	echo "    $0 unit uninstalltoken"
}

if [ $# -ge 1 ] && [ "$1" = "-h" ];then
	Usage
	exit 0
fi

echo "======== AntiAPT EDR ========"
echo "==== `date` : `pwd` ====" >> $LOG

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

# 解析可用的安装版本, 有新增或修改需要和user/make_avira中保持统一
if [ -f /proc/version ]; then
   #兼容从centos改的系统，比如湖南麒麟3.10.0-957.ky3.kb3.x86_64
   os=`uname -r | grep -E "[4.18.0|3.10.0|2.6.32|2.6.18|5.15.10|5.16.]"`
   if [ -n "$os" ]; then
        os_dist='CentOS'

        os=`awk '{print $3}' /proc/version | sed 's/[-|.]/\n/g'`

        ver1=`echo $os |awk {'print $1'}`
        ver2=`echo $os |awk {'print $2'}`
        ver3=`echo $os |awk {'print $3'}`
        ver4=`echo $os |awk {'print $4'}`

        #5.0-5.11
        if [ "$ver1" -eq 2 ] && [ "$ver2" -eq 6 ] && [ "$ver3" -eq 18 ]; then
                os_ver=5
		if [ "$ver4" -ge 398 ]; then
			kern_ver=5.11
		elif [ "$ver4" -ge 371 ]; then
			kern_ver=5.10
		elif [ "$ver4" -ge 348 ]; then
			kern_ver=5.9
		elif [ "$ver4" -ge 308 ]; then
			kern_ver=5.8
		elif [ "$ver4" -ge 274 ]; then
			kern_ver=5.7
		elif [ "$ver4" -ge 238 ]; then
			kern_ver=5.6
		elif [ "$ver4" -ge 194 ]; then
			kern_ver=5.5
		elif [ "$ver4" -ge 164 ]; then
			kern_ver=5.4
		elif [ "$ver4" -ge 128 ]; then
			kern_ver=5.3
		elif [ "$ver4" -ge 92 ]; then
			kern_ver=5.2
		elif [ "$ver4" -ge 53 ]; then
			kern_ver=5.1
		else
			kern_ver=5.0
		fi
        fi

        #6.0-6.10
        if [ "$ver1" -eq 2 ] && [ "$ver2" -eq 6 ] && [ "$ver3" -eq 32 ]; then
                os_ver=6
		if [ "$ver4" -ge 754 ]; then
			kern_ver=6.10
		elif [ "$ver4" -ge 696 ]; then
			kern_ver=6.9
		elif [ "$ver4" -ge 642 ]; then
			kern_ver=6.8
		elif [ "$ver4" -ge 573 ]; then
			kern_ver=6.7
		elif [ "$ver4" -ge 504 ]; then
			kern_ver=6.6
		elif [ "$ver4" -ge 431 ]; then
			kern_ver=6.5
		elif [ "$ver4" -ge 358 ]; then
			kern_ver=6.4
		elif [ "$ver4" -ge 279 ]; then
			kern_ver=6.3
		elif [ "$ver4" -ge 220 ]; then
			kern_ver=6.2
		elif [ "$ver4" -ge 131 ]; then
			kern_ver=6.1
		else
			kern_ver=6.0
		fi
        fi

        # 7.0-7.9
        if [ "$ver1" -eq 3 ] && [ "$ver2" -eq 10 ] && [ "$ver3" -eq 0 ]; then
                os_ver=7
		if [ "$ver4" -ge 1160 ]; then
			kern_ver=7.9
		elif [ "$ver4" -ge 1127 ]; then
			kern_ver=7.8
		elif [ "$ver4" -ge 1062 ]; then
			kern_ver=7.7
		elif [ "$ver4" -ge 957 ]; then
			kern_ver=7.6
		elif [ "$ver4" -ge 862 ]; then
			kern_ver=7.5
		elif [ "$ver4" -ge 693 ]; then
			kern_ver=7.4
		elif [ "$ver4" -ge 514 ]; then
			kern_ver=7.3
		elif [ "$ver4" -ge 327 ]; then
			kern_ver=7.2
		elif [ "$ver4" -ge 229 ]; then
			kern_ver=7.1
		else
			kern_ver=7.0
		fi
        fi

        # 8.0-8.4
        if [ "$ver1" -eq 4 ] && [ "$ver2" -eq 18 ] && [ "$ver3" -eq 0 ]; then
                os_ver=8
		if [ "$ver4" -ge 305 ]; then
			kern_ver=8.4
		elif [ "$ver4" -ge 240 ]; then
			kern_ver=8.3
		elif [ "$ver4" -ge 193 ]; then
			kern_ver=8.2
		elif [ "$ver4" -ge 147 ]; then
			kern_ver=8.1
		else
			kern_ver=8.0
		fi
        fi

	# centos7内核升级到5.15.10视为7.10，升级到5.16.1视为7.11
        if [ "$ver1" -eq 5 ] && [ "$ver2" -eq 15 ] && [ "$ver3" -eq 10 ]; then
                os_ver=7
		kern_ver=7.10
	fi
	if [ "$ver1" -eq 5 ] && [ "$ver2" -eq 16 ]; then
                os_ver=7
		if [ "$ver3" -lt 7 ]; then
			kern_ver=7.11
		else
			kern_ver=7.12
		fi
	fi

	# 支持神州灵云oem项目
	os=`awk '{print $3}' /proc/version`
	if [ "$os" = "2.6.32-300.10.1.el5uek" ]; then
		os_ver=5
		kern_ver=5.8uek
	fi
   fi

   # oracle linux内核升级到4.1.12-94.3.9.el7uek.x86_64视为7.13
   os=`grep -i 'Red Hat' /proc/version`
   if [ -n "$os" ]; then
	os_dist='CentOS'

	if [ -f /etc/os-release ]; then
		os=`grep "7.4" /etc/os-release`
		if [ "$os" != "" ]; then
			os_ver=7
		fi

		os=`awk '{print $3}' /proc/version`
		if [ "$os" = "4.1.12-94.3.9.el7uek.x86_64" ]; then
			kern_ver=7.13
		fi
	fi
   fi

   os=`grep -i ubuntu /proc/version`
   if [ -n "$os" ]; then
	os_dist='Ubuntu'

	os=`grep "16.04" /etc/os-release`
	if [ "$os" != "" ]; then
		os_ver=16.04
	fi

	os=`grep "18.04" /etc/os-release`
	if [ "$os" != "" ]; then
		os_ver=18.04
	fi

	os=`awk '{print $3}' /proc/version`
	if [ "$os" = "4.15.0-132-generic" ]; then
		kern_ver=4.15.0-132
	fi
	if [ "$os" = "4.4.0-210-generic" ]; then
		kern_ver=4.4.0-210
	fi
	if [ "$os" = "4.15.0-122-generic" ]; then
		kern_ver=4.15.0-122
	fi
   fi

   os=`grep -i suse /proc/version`
   if [ -n "$os" ]; then
        os_dist='SUSE'

        os=`awk '{print $3}' /proc/version | sed 's/[-|.]/\n/g'`

        ver1=`echo $os |awk {'print $1'}`
        ver2=`echo $os |awk {'print $2'}`
        ver3=`echo $os |awk {'print $3'}`
        ver4=`echo $os |awk {'print $4'}`

        # 11.4
        if [ "$ver1" -eq 3 ] && [ "$ver2" -eq 0 ] && [ "$ver3" -eq 101 ]; then
                os_ver=11
		kern_ver=11.4
        fi

        # 12.4/5，15.1
        if [ "$ver1" -eq 4 ] && [ "$ver2" -eq 12 ] && [ "$ver3" -eq 14 ]; then
		if [ "$ver4" -ge 195 ]; then
                	os_ver=15
			kern_ver=15.1
		elif [ "$ver4" -ge 120 ]; then
                	os_ver=12
			kern_ver=12.5
		elif [ "$ver4" -ge 94 ]; then
                	os_ver=12
			kern_ver=12.4
		fi
        fi
   fi

   os=`grep -i kylin /etc/*release`
   if [ -n "$os" ]; then
      os=`awk '{print $3}' /proc/version`
      if [ "$os" = "4.19.90-17.ky10.aarch64" ]; then
         os_dist='KylinServer'
         os_ver=10
         kern_ver=4.19.90-17
      elif [ "$os" = "4.19.90-24.4.v2101.ky10.aarch64" ]; then
         os_dist='KylinServer'
         os_ver=10
	 kern_ver=4.19.90-24
      elif [ "$os" = "5.4.18-27-generic" ]; then
         os_dist='KylinDesktop'
         os_ver=10
	 kern_ver=5.4.18-27
      elif [ "$os" = "5.4.18-35-generic" ]; then
         os_dist='KylinDesktop'
         os_ver=10
	 kern_ver=5.4.18-35

      elif [ "$os" = "4.19.90-21.2.ky10.x86_64" ]; then
         os_dist='KylinServer'
         os_ver=10
         kern_ver=4.19.90-21
      elif [ "$os" = "4.19.90-24.4.v2101.ky10.x86_64" ]; then
         os_dist='KylinServer'
         os_ver=10
         kern_ver=4.19.90-24
      fi
   fi
fi

use_rh6=`ls -l /usr/lib64/libcrypto.so.10 2>/dev/null | grep libcrypto.so.1.0.0`

# 根据内核确定的os_ver和kern_ver，但centos可能仅升级内核，故修正os_ver，使得仍用老的os_ver
if [ "$os_dist" = "CentOS" ]; then
	./$os_arch/$os_dist/$os_ver/ngep -v >/dev/null 2>&1
	if [ $? -ne 0 ]; then
		for i in 5 6 7 8
		do
			./$os_arch/$os_dist/$i/ngep -v >/dev/null 2>&1
			if [ $? -eq 0 ]; then
				os_ver=$i
				break
			fi
		done
	fi
fi

if [ "$os_ver" = "" ]; then
	os=`uname -a 2>/dev/null`
	if [ "$os" = "" ]; then
		os=`cat /proc/version`
	fi
	echo "Install Sniper Fail"
	echo "Kernel not supported by this package"
	echo "Kernel: $os"
	echo "May require a higher version install package"
	exit 1
fi
if [ "$kern_ver" = "" ]; then
	kern_ver=$os_ver
fi
echo "install dir: ./$os_arch/$os_dist/$kern_ver/" >> $LOG

chmod +x ./$os_arch/$os_dist/$os_ver/*
chmod -x ./$os_arch/$os_dist/$os_ver/*.* ./$os_arch/$os_dist/$os_ver/sniper_cron

# show distribution release
show_release()
{
	if [ -f /etc/system-release ]; then
		osrelease=`cat /etc/system-release`
		if [ "$osrelease" != "" ]; then
			echo "OS: $osrelease"
			return
		fi
	fi

	if [ -f /etc/centos-release ]; then
		osrelease=`cat /etc/centos-release`
		if [ "$osrelease" != "" ]; then
			echo "OS: $osrelease"
			return
		fi
	fi

	if [ -f /etc/redhat-release ]; then
		osrelease=`cat /etc/redhat-release`
		if [ "$osrelease" != "" ]; then
			echo "OS: $osrelease"
			return
		fi
	fi

	if [ -f /etc/lsb-release ]; then
		osrelease=`grep DISTRIB_DESCRIPTION /etc/lsb-release | cut -s -f2 -d'='`
		if [ "$osrelease" != "" ]; then
			echo "OS: $osrelease"
			return
		fi
	fi

	if [ -f /etc/os-release ]; then
		osrelease=`grep PRETTY_NAME /etc/os-release | cut -s -f2 -d'='`
		if [ "$osrelease" != "" ]; then
			echo "OS: $osrelease"
			return
		fi
	fi
}
show_release

# stop sniper. Do clean?
if [ $# -eq 2 ] && [ "$1" = "unit" ];then
	echo "Uninstall ..."

	if [ "$use_rh6" = "" ]; then
		./$os_arch/$os_dist/$os_ver/sniper --uninstall $2
	else
		./$os_arch/RedHat/$os_ver/sniper --uninstall $2
	fi
	if [ $? -gt 0 ]; then
		echo "Sniper ${OLDVERSION} uninstall FAIL"
		echo "Sniper ${OLDVERSION} uninstall FAIL" >> $LOG
		exit 1
	fi

	sed -i "/sniper/d" /etc/rc.local 2>/dev/null
	sed -i "/sniper/d" /etc/rc.d/rc.local 2>/dev/null

	rm -f /sbin/sniper /sbin/assist_sniper /bin/sniper_antivirus /etc/sniper.conf
	rm -f /etc/cron.d/sniper* /etc/xdg/autostart/snipertray.desktop
	rm -f /var/run/antiapt.* /var/run/assist.pid
	rm -f /etc/sniper-installtoken
	rm -rf /opt/snipercli

	# 卸载时sku不删

	# TODO 删除各用户的.snipertray.pid文件
	plist=`ps -C snipertray -o pid=`
	if [ "$plist" != "" ]
	then
		echo "$plist" | xargs kill -9
	fi

	# 删除防勒索陷阱文件
	find / -maxdepth 3 -type f -name "[a-z]*_safe_file\.*" -exec rm -f "{}" \;   2>/dev/null
	find / -maxdepth 3 -type f -name "\.[a-z]*_safe_file\.*" -exec rm -f "{}" \; 2>/dev/null

	echo "== Sniper ${OLDVERSION} uninstalled =="
	echo "== Sniper ${OLDVERSION} uninstalled ==" >> $LOG

	exit 0
fi

if [ ! -f ./$os_arch/$os_dist/$os_ver/sniper -o ! -f ./$os_arch/$os_dist/$kern_ver/sniper_edr.ko ]; then
	echo "Fail: no install file in $os_arch/$os_dist/$os_ver"
	echo "Fail: no install file in $os_arch/$os_dist/$os_ver" >> $LOG
	exit 1
fi

if [ -d /usr/lib/x86_64-linux-gnu/ ]; then
        LIBDIR="/usr/lib/x86_64-linux-gnu"
else
        LIBDIR="/usr/lib64"
fi

copy_avira_lib()
{
        avira_lib=`ls ./$1.so* 2>/dev/null`
        if [ "$avira_lib" != "" ]; then
                libname=`basename $avira_lib`
                if [ "$libname" != "" -a -f $avira_lib ]
                then
                        # 库已存在不拷
                        if [ ! -f ${LIBDIR}/${libname} ]
                        then
                                echo "Copy ${libname}"
                                cp -f $avira_lib $LIBDIR
                        fi
                fi
        fi
}

# 拷贝病毒防护线程用到的动态库，必须放在检查卸载之前，否则执行卸载检查的时候由于没有加载到库停止运行
copy_avira_lib $os_arch/libiconv
copy_avira_lib $os_arch/libsavapi

seemore()
{
	if [ -f /var/log/antiapt.status ]; then
		echo ""
		grep -v " id " /var/log/antiapt.status
		echo ""
	fi

	echo "More see /tmp/sniper-install-error.txt"
	tail -n 20 /var/log/antiapt.log | grep -v " done" > /tmp/sniper-install-error.txt
	echo "[more see /var/log/antiapt.log]" >> /tmp/sniper-install-error.txt
	echo "" >> /tmp/sniper-install-error.txt
	echo "" >> /tmp/sniper-install-error.txt

	dmesg | tail -n 10 >> /tmp/sniper-install-error.txt
	echo "[more do \"dmesg\"]" >> /tmp/sniper-install-error.txt
}

# stop old monitor before install
echo "Check old version and stop it ..."
if [ "$1" = "update" ]; then
	echo Update

	# 取升级前的客户端程序名
        pid=$$
        while [ $pid -gt 300 ]
        do
                ppid=`grep PPid /proc/$pid/status | awk '{print $2}'`
                pkg=`cat /proc/$ppid/cmdline | tr "\0" "\n" | grep "linux.*bin"`
                if [ "$pkg" != "" ]; then
                        break
                fi
                pid=$ppid
        done
        caller=`basename $pkg | cut -f1 -d"-"`

	# 安装包改名升级时，比如从myhp升级到ngep，延用老的conf和sku
	if [ "$caller" != "sniper" ]; then
		cp -f /etc/${caller}.conf /etc/sniper.conf
		cp -f /etc/${caller}-sku /etc/sniper-sku
	fi

	echo Stop old ${caller}
	# 升级时在antiapt.log里记录停止过程中的错误，便于查错
	if [ "$use_rh6" = "" ]; then
		./$os_arch/$os_dist/$os_ver/sniper -s ZH94f2JlcH19Tnx0
	else
		./$os_arch/RedHat/$os_ver/sniper -s ZH94f2JlcH19Tnx0
	fi
else
	if [ "$use_rh6" = "" ]; then
		./$os_arch/$os_dist/$os_ver/sniper -s ZH94f2JlcH19Tnx0 >/dev/null 2>&1
	else
		./$os_arch/RedHat/$os_ver/sniper -s ZH94f2JlcH19Tnx0 >/dev/null 2>&1
	fi
fi
if [ $? -gt 0 ]; then
	echo "Sniper install FAIL. [stop old sniper fail]"
	echo "Sniper install FAIL. [stop old sniper fail]" >> $LOG
	echo

	if [ "$use_rh6" = "" ]; then
		./$os_arch/$os_dist/$os_ver/sniper -t
	else
		./$os_arch/RedHat/$os_ver/sniper -t
	fi

	seemore

	exit 1
fi

# 删除老的cron任务
cronlist=`cd /etc/cron.d; ls *_cron 2>/dev/null`
if [ "$cronlist" != "" ]; then
	for cron in $cronlist
	do
		name=`echo $cron | cut -f1 -d'_'`
		grep "${name}_chk" /etc/cron.d/$cron >/dev/null 2>&1
		if [ $? -eq 0 ]
		then
			echo "delete old $cron task" >> $LOG
			rm -f /etc/cron.d/$cron
		fi
	done
fi

# 删除防勒索陷阱文件
find / -maxdepth 3 -type f -name "[a-z]*_safe_file\.*" -exec rm -f "{}" \;   2>/dev/null
find / -maxdepth 3 -type f -name "\.[a-z]*_safe_file\.*" -exec rm -f "{}" \; 2>/dev/null

# 5.0.6修改了日志发送机制，在offlinelog目录之下又细分了类别子目录，批量日志放在子目录里等待上传
# 清理5.0.6之前的offlinelog目录下的离线日志，避免离线日志存储空间被老的残留日志给占满了，导致新的日志不上传
find /opt/snipercli/offlinelog/ -maxdepth 1 -type f -name "*.log" -exec rm -f "{}" \; 2>/dev/null

rm -f /sbin/sniper
rm -f /sbin/assist_sniper
rm -f /bin/sniper_antivirus
if [ "$use_rh6" = "" ]; then
	echo "Copy $os_arch $os_dist $os_ver files ..."
	/bin/cp -f ./$os_arch/$os_dist/$os_ver/${CMD} /sbin/
	/bin/cp -f ./$os_arch/$os_dist/$os_ver/${ASSIST_CMD} /sbin/
	if [ -f ./$os_arch/$os_dist/$os_ver/${ANTIVIRUS_CMD} ]; then
		/bin/cp -f ./$os_arch/$os_dist/$os_ver/${ANTIVIRUS_CMD} /bin/
	fi
else
	echo "Copy $os_arch RedHat $os_ver files ..."
	/bin/cp -f ./$os_arch/RedHat/$os_ver/${CMD} /sbin/
	/bin/cp -f ./$os_arch/RedHat/$os_ver/${ASSIST_CMD} /sbin/
	if [ -f ./$os_arch/RedHat/$os_ver/${ANTIVIRUS_CMD} ]; then
		/bin/cp -f ./$os_arch/RedHat/$os_ver/${ANTIVIRUS_CMD} /bin/
	fi
fi

echo "Copy $os_arch $os_dist $kern_ver ${MOD} ..."
/bin/cp -f ./$os_arch/$os_dist/$kern_ver/${MOD}.ko ${KMOD_LOCATION}

if [ -f ./$os_arch/$os_dist/$kern_ver/${MOD}.sign.ko ]
then
	insmod_result=`insmod ./$os_arch/$os_dist/$kern_ver/${MOD}.ko 2>&1 | grep "Required key not available"`
	rmmod ${MOD} 2>/dev/null
	if [ "$insmod_result" != "" ]
	then
		echo "Copy $os_arch $os_dist $kern_ver ${MOD}.sign ..."
		/bin/cp -f ./$os_arch/$os_dist/$kern_ver/${MOD}.sign.ko ${KMOD_LOCATION}/${MOD}.ko

		insmod_result=`insmod ./$os_arch/$os_dist/$kern_ver/${MOD}.sign.ko 2>&1 | grep "Required key not available"`
		rmmod ${MOD} 2>/dev/null
		if [ "$insmod_result" != "" ]
		then
			sbstat=`mokutil --sb-state 2>/dev/null | grep enabled`
		fi
	fi
fi

notstripped=`file /sbin/sniper | grep "not stripped"`
if [ "$notstripped" != "" ]
then
	echo
	echo "Warning:"
	echo "         sniper NOT stripped! remember strip when release"
	echo
fi

copycli()
{
	oldfile="/opt/snipercli/$1"
	if [ -f ${oldfile} ]
	then
		diff -b $1 ${oldfile} >/dev/null 2>&1
		if [ $? -eq 0 ]
		then
			# 相同的程序不拷
			return
		fi
		/bin/mv -f ${oldfile} /opt/snipercli/.$1.old
	fi
	/bin/cp -f $1 /opt/snipercli/
}

workdir=`pwd`

# redhat6的库还是用centos6的
if [ "$use_rh6" != "" ]
then
	cd ./$os_arch/RedHat/$os_ver/
	for ss in sniper* systeminformation assist* 
	do
		copycli $ss
	done

	cd $workdir
	cd ./$os_arch/$os_dist/$os_ver/
	for ss in lib*
	do
		if [ "$ss" = "lib*" ]; then
			break #没有库要拷
		fi
		copycli $ss
	done
else
	cd ./$os_arch/$os_dist/$os_ver/
	for ss in sniper* systeminformation assist* lib*
	do
		if [ "$ss" = "lib*" ]; then
			continue #没有库要拷
		fi
		copycli $ss
	done
fi

# 改名.sniper.a
/bin/mv /opt/snipercli/sniper.a /opt/snipercli/.sniper.a

cd ${workdir}
# 拷贝sniper_location.db
copycli sniper_location.db
# 拷贝证书
copycli x509.der

cd $os_arch
# 拷贝webshell_detector
copycli webshell_detector
# 拷贝webshell检测静态文件
cp -rf static /opt/snipercli/
# 拷贝防病毒的依赖文件
cp -rf bin /opt/snipercli/
# 拷贝防病毒的库文件
#cp -rf vdf /opt/snipercli/

cd ${workdir}

if [ -d /etc/xdg/autostart ]
then
	/bin/cp -f ./$os_arch/$os_dist/$os_ver/snipertray.desktop /etc/xdg/autostart/
else
	echo "no /etc/xdg/autostart/"
fi

if [ $os_dist = "CentOS" -a "$os_ver" = "8" ]
then
	if [ ! -d /usr/share/gnome-shell/extensions/top-icons@gnome-shell-extensions.gcampax.github.com ]
	then
		/bin/cp -rf ./$os_arch/$os_dist/$os_ver/top-icons@gnome-shell-extensions.gcampax.github.com /usr/share/gnome-shell/extensions/
		chmod +x /usr/share/gnome-shell/extensions/top-icons@gnome-shell-extensions.gcampax.github.com
	fi

	if [ ! -d /usr/lib64/qt5/plugins/platforms ]
	then
		/bin/mkdir -p /usr/lib64/qt5/plugins/ 
		/bin/cp -rf ./$os_arch/$os_dist/$os_ver/platforms /usr/lib64/qt5/plugins/
	fi

fi

copylib()
{
        qtlib=`ls ./$os_arch/$os_dist/$os_ver/$1.so.$2* 2>/dev/null`
        if [ "$qtlib" != "" ]; then
                qtlibname=`basename $qtlib`
                if [ "$qtlibname" != "" -a -f $qtlib ]
                then
                        # 库已存在不拷
                        if [ ! -f ${LIBDIR}/${qtlibname} ]
                        then
                                echo "Copy ${qtlibname}"
                                cp -f $qtlib $LIBDIR
                        fi
                        ln -sf $qtlibname $LIBDIR/$1.so.$2
                fi
        fi
}
copylib libpcre2-16 0
copylib libxcb-image 0
copylib libxcb-render-util 0
copylib libxcb-keysyms 1
copylib libxcb-icccm 4

copylib libQtCore 4
copylib libQtGui 4
copylib libQt5Core 5
copylib libQt5Gui 5
copylib libQt5Widgets 5
copylib libQt5XcbQpa 5
copylib libQt5DBus 5


#将安装文件所有者改成root
chown -R root:root ${LOCATION}
chown root:root /sbin/sniper
chown root:root /sbin/assist_sniper
chown root:root /etc/xdg/autostart/snipertray.desktop
chown root:root /opt/snipercli/sniper_location.db
chown root:root /opt/snipercli/webshell_detector
chown root:root ${KMOD_LOCATION}/${MOD}.ko

chmod +x /sbin/sniper
chmod +x /sbin/assist_sniper
if [ -f /bin/sniper_antivirus ];then
	chmod +x /bin/sniper_antivirus
fi
chmod +x /opt/snipercli/webshell_detector
chmod +x /opt/snipercli/sniper_chk >/dev/null 2>&1
chmod +x /opt/snipercli/assist_sniper_chk >/dev/null 2>&1
chmod +x /opt/snipercli/static >/dev/null 2>&1
chmod +x /opt/snipercli/bin >/dev/null 2>&1
#chmod +x /opt/snipercli/vdf >/dev/null 2>&1

chmod -x /etc/cron.d/sniper_cron >/dev/null 2>&1

#后台做depmod，缩短安装时间
nohup /sbin/depmod -a > /dev/null 2>&1 &

#准备好了module再拷贝sniper_cron，避免时间过长，sniper_cron起了sniper，导致下面起sniper失败
echo "add sniper_cron task" >> $LOG
/bin/cp -f ./$os_arch/$os_dist/$os_ver/sniper_cron /etc/cron.d/
chown root:root /etc/cron.d/sniper_cron

if [ $# -eq 0 ]
then
	ppid=`grep PPid /proc/$$/status | awk '{print $2}'`
	servinfo=`cat /proc/$ppid/cmdline | cut -s -f2 -d'(' | cut -s -f1 -d')'`
	if [ "$servinfo" != "" ]
	then
        	server=`echo $servinfo | cut -s -f1 -d'_'`
	        port=`echo $servinfo | cut -s -f2 -d'_' | cut -s -f1 -d'@'`
	fi

	if [ "$server" = "" -o "$port" = "" ]
	then
		echo
		if [ -x /opt/snipercli/sniper_servaddr ]
		then
			# sniper_servaddr失败，尝试终端输入参数
			/opt/snipercli/sniper_servaddr 2>/dev/null
			if [ $? -eq 0 ]
			then
        			server=`cat /etc/sniper.conf | grep -v "#" | awk -F: '{print $1}'`
	        		port=`cat /etc/sniper.conf | grep -v "#" | awk -F: '{print $2}'`
			else
				read -p "Server name or ip: " server
				read -p "Server port: " port
			fi
		else
			read -p "Server name or ip: " server
			read -p "Server port: " port
		fi
	fi
else
	if [ "$1" = "update" ]
	then
		if [ "$caller" != "" -a "$caller" != "sniper" ]; then
			echo "Copy ${caller} data to sniper"
			cp -f /opt/${caller}cli/current_server /opt/snipercli/ 2>/dev/null
			cp -f /opt/${caller}cli/.language /opt/snipercli/ 2>/dev/null
			cp -f /opt/${caller}cli/.nodeinfo /opt/snipercli/ 2>/dev/null
			cp -f /opt/${caller}cli/.update_task_information /opt/snipercli/ 2>/dev/null
			cp -f /opt/${caller}cli/policy.zip.lst /opt/snipercli/ 2>/dev/null
			cp -f /opt/${caller}cli/conf.json /opt/snipercli/ 2>/dev/null
			cp -f /opt/${caller}cli/rule.json /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/.mondb /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/.filedb /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/.virusdb /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/.filebackup /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/.pid /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/log /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/sample /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/offlinelog /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/static /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/bin /opt/snipercli/ 2>/dev/null
#			cp -rf /opt/${caller}cli/vdf /opt/snipercli/ 2>/dev/null
			cp -rf /opt/${caller}cli/*.version /opt/snipercli/ 2>/dev/null

			sed -i "/${caller}/d" /etc/rc.local 2>/dev/null
			sed -i "/${caller}/d" /etc/rc.d/rc.local 2>/dev/null
			rm -rf /opt/${caller}cli/ /sbin/${caller}
		fi

        	server=`cat /etc/sniper.conf | grep -v "#" | awk -F: '{print $1}'`
	        port=`cat /etc/sniper.conf | grep -v "#" | awk -F: '{print $2}'`
	else
        	server=$(echo $1|awk -F: '{print $1}')
	        port=$(echo $1|awk -F: '{print $2}')
	fi
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

if [ $# -ne 1 -o "$1" != "update" ]
then
	check_server
	if [ $validserver -eq 0 ]
	then
		Usage
		exit 1
	fi

	# 清除上次的服务器配置缓存
	rm -f /opt/snipercli/current_server
	# 保存服务器配置
	echo "$server:$port" > /etc/sniper.conf
	echo "$server:$port" >> $LOG
fi


# if app not autostart, set autostart
CMD="/sbin/sniper >/dev/null 2>&1 &"
auto_sniper()
{
	grep -w sniper $1 > /dev/null 2>&1
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

ASSIST_CMD="/sbin/assist_sniper >/dev/null 2>&1 &"
auto_assist_sniper()
{
	grep -w assist_sniper $1 > /dev/null 2>&1
	if [ $? -ne 0 ]
	then
		# check if there is a "exit 0" at end (like ubuntu)
		grep -r "^[[:space:]]*exit 0" $1 >/dev/null 2>&1
		if [ $? -ne 0 ]
		then
			# append to the end
			echo ${ASSIST_CMD} >> $1
		else
			# insert before "exit 0"
			sed -i "/^[[:space:]]*exit[[:space:]]*0/i ${ASSIST_CMD}" $1
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

if [ "$sbstat" != "" ]
then
	echo
	echo "Machine in SecureBoot mode"
	echo "${MOD} modele needs to be signed"
	echo "Please do \"mokutil --import /opt/snipercli/x509.der\", then reboot"
	exit 0
fi

echo "Install ..."

cd /
/sbin/sniper >/dev/null 2>&1 &
/sbin/assist_sniper >/dev/null 2>&1 &

#ZX20200807 针对ledr sku重复的问题，改变了构建sku的规则，这里打印确认一下安装前是否成功删除了老的sku
if [ "$oldsku" != "" ]
then
	echo "Use existing sku: $oldsku"
else
	newsku=`cat /etc/sniper-sku 2>/dev/null | tr -d '\r\n\0'`
	if [ "$newsku" != "" ]
	then
		echo "Set sku: $newsku"
	fi
fi

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
	echo "Sniper install FAIL"
	echo "Sniper install FAIL" >> $LOG

	seemore
 
	exit 1
fi

PID=`cat /var/run/antiapt.pid | tr -d '\r\n\0'`
sniper_on=`ps -p $PID -o comm=`
if [ "$sniper_on" != "sniper" ]
then
	echo "antiapt.pid: $PID." >> $LOG 2>&1
	echo "ps -p $PID -o comm=" >> $LOG
	ps -p $PID -o comm= >> $LOG 2>&1
	echo "==1st==" >> $LOG

	/sbin/sniper >/dev/null 2>&1 &
	sleep 1
	PID=`cat /var/run/antiapt.pid | tr -d '\r\n\0'`
	sniper_on=`ps -p $PID -o comm=`
	if [ "$sniper_on" != "sniper" ]
	then
		echo "antiapt.pid: $PID." >> $LOG 2>&1
		echo "ps -p $PID -o comm=" >> $LOG
		ps -p $PID -o comm= >> $LOG 2>&1
		echo "==2nd==" >> $LOG

		modfail=`grep "load module fail" /var/run/antiapt.status 2>/dev/null`
		if [ "$modfail" != "" ]; then
			echo "Load sniper_edr module fail"
			echo "Load sniper_edr module fail" >> $LOG
		else
			echo "Run sniper fail"
			echo "Run sniper fail" >> $LOG
		fi

		echo "Sniper install FAIL" 
		echo "Sniper install FAIL" >> $LOG

		seemore

		/sbin/sniper -s ZH94f2JlcH19Tnx0

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

echo "== Sniper ${NEWVERSION} installed =="
echo "== Sniper ${NEWVERSION} installed ==" >> $LOG

# 起托盘程序

# 清理老的托盘运行环境临时文件
rm -f /tmp/snipertrayenv.*
# 保存当前运行着的所有snipertray类的运行环境
# 遍历所有的snipertray类启动任务，考虑到改名升级的情况，主机上可能有多个snipertray类启动任务
traylist=`cd /etc/xdg/autostart/; ls *tray.desktop 2>/dev/null`
if [ "$traylist" != "" ]
then
	for tray in $traylist
	do
		name=`echo $tray | sed -s "s/tray.desktop//g"`

		# 确认启动任务是snipertray类
		grep "Exec=.*/${name}tray" /etc/xdg/autostart/${tray} >/dev/null 2>&1
		if [ $? -ne 0 ]; then
			continue;
		fi
		grep "Icon=.*/${name}.png" /etc/xdg/autostart/${tray} >/dev/null 2>&1
		if [ $? -ne 0 ]; then
			continue;
		fi

		# 获取托盘程序的进程列表，可能有多个托盘程序，每个图形登录的用户有一个
		plist=`ps -C ${name}tray -o pid=`
		if [ "$plist" != "" ]; then
			for pid in $plist
			do
				# 保存托盘程序的运行环境
				uid=`ls -dlLn /proc/$pid/ | awk '{print $3}'`
				cat /proc/$pid/environ | tr "\0" "\n" > /tmp/snipertrayenv.$uid
				# 终止老的托盘程序
				kill -9 $pid
			done
		fi

		# 删除老的改名前的tray启动任务
		if [ "$name" != "sniper" ]; then
			rm -f /etc/xdg/autostart/${tray}
		fi
	done
fi
# 遍历上面保存的所有的托盘运行环境，重起托盘
traylist=`cd /tmp/; ls snipertrayenv.* 2>/dev/null`
if [ "$traylist" != "" ]
then
	for tray in $traylist
	do
		uid=`echo $tray | cut -f2 -d'.'`
		restart_snipertray $uid
	done
fi

if [ "$1" != "update" ]
then
	start_snipertray
fi


# 模块没起来，不算安装失败 TODO 由sniper报告模块未加载日志
MOD=`lsmod | grep -w sniper_edr`
if [ "$MOD" = "" ]
then
	sleep 1
	MOD=`lsmod | grep -w sniper_edr`
fi
if [[ "$MOD" != "" ]] || [[ -f "/tmp/nomodule.df" ]]
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

seemore

exit 0
