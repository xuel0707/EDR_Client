start=`date +%s`
echo "----------`hostname` : start build----------"

end_print()
{
	end=`date +%s`
	used_time=`expr $end - $start`
	echo "----------`hostname` : build end, use ${used_time}s----------"
}

kern_ver=`uname -r`

is_centos=`grep -i centos /etc/*-release`
if [ "$is_centos" != "" ]
then
	six=`grep 2.6.18 /proc/version`
	if [ "$six" != "" ]
	then
		sh mk-centos5 $1
		end_print
		exit 0
	fi

	six=`grep 2.6.32 /proc/version`
	if [ "$six" != "" ]
	then
		sh mk-centos6 $1
		end_print
		exit 0
	fi

	seven=`grep 3.10.0 /proc/version`
	if [ "$seven" != "" ]
	then
		sh mk-centos7 $1
		end_print
		exit 0
	fi

	eight=`grep 4.18.0 /proc/version`
	if [ "$eight" != "" ]
	then
		sh mk-centos8 $1
		end_print
		exit 0
	fi
fi

is_ub16046=`grep 16.04.6 /etc/*-release`
if [ "$is_ub16046" != "" ]
then
	sh mk-ub16046 $1
	end_print
	exit 0
fi

is_ub18045=`grep 18.04.5 /etc/*-release`
if [ "$is_ub18045" != "" ]
then
	sh mk-ub18045 $1
	end_print
	exit 0
fi
is_suse11=`grep -i "suse.*11" /etc/*-release`
if [ "$is_suse11" != "" ]
then
	sh mk-suse11 $1
	end_print
	exit 0
fi

is_suse12=`grep -i "suse.*12" /etc/*-release`
if [ "$is_suse12" != "" ]
then
	sh mk-suse12 $1
	end_print
	exit 0
fi

is_suse15=`grep -i "suse.*15" /etc/*-release`
if [ "$is_suse15" != "" ]
then
	sh mk-suse15 $1
	end_print
	exit 0
fi

is_ky10server=`grep -i "kylin.*server.*v10" /etc/*-release`
if [ "$is_ky10server" != "" ]
then
	sh mk-kylin-v10-server.x86_64 $1
	end_print
	exit 0
fi

is_oraclelinux=`grep -i "Oracle Linux" /etc/*-release`
if [ "$is_oraclelinux" != "" ]
then
	sh mk-oraclelinux7 $1
	end_print
	exit 0
fi

make $1
end_print
