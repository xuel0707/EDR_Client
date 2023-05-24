#!/bin/bash -x
# 用法：sh ngep-release-centos-ub16046-suse.sh ngep-linux-5.0.9.220606 regular

# 拉取最新代码

# 将sniper替换成ngep
echo "use /home/ngep"
echo
if [ ! -d /home/ngep ]
then
	echo "no /home/ngep"
	exit
fi

#设置产品名
echo "replace sniper with ngep"
cd /home/ngep/
find . -type f -exec touch {} \;
make clean
cp -f include/vendor_sniper.h include/vendor_ngep.h
cp -f user/antivirus/sniper_antivirus.c user/antivirus/ngep_antivirus.c
cp -f qt/logo/sniper-server-setting.desktop qt/logo/ngep-server-setting.desktop
cp -f qt/logo/snipertray.desktop qt/logo/ngeptray.desktop
cp -f qt/logo/sniper.png qt/logo/ngep.png
cp -f tools/sniper_cron tools/ngep_cron
cp -f tools/sniper_chk tools/ngep_chk
cp -f tools/assist_sniper_chk tools/assist_ngep_chk
cp -f tools/build-sniper-linux.sh tools/build-ngep-linux.sh
cp -f check_sniper_strip check_ngep_strip
cp -f doc/sniper_location.db doc/ngep_location.db
cp -rf deb/sniper deb/ngep

#替换关键字，为了加快速度，排除了一些目录。优化后快了1分钟
find ./ -path ./.git -prune -o -path ./oem -prune -o -path ./external -prune -o -path ./selftest -prune -o -path ./doc -prune -o -type f -exec sed -i -e "s/sniper/ngep/g" -e "s/Sniper/Ngep/g" -e "s/SNIPER/NGEP/g" "{}" \;

#外部代码cloudwalker里用到了/opt/sniprcli目录，也要替换
find ./external/cloudwalker -type f -exec sed -i -e "s/sniper/ngep/g" -e "s/Sniper/Ngep/g" -e "s/SNIPER/NGEP/g" "{}" \;


#cloudwalker源码打包
cd /home/ngep/external
tar zcf /tmp/cloudwalker.tar.gz cloudwalker/ 

#到centos7.1上编译webshell引擎
echo "copy new cloudwalker to centos7.1"
ssh centos7.1 rm -rf /home/cloudwalker
scp -r /tmp/cloudwalker.tar.gz root@centos7.1:/tmp/    >/dev/null

ssh centos7.1 "cd /home; tar -zxf /tmp/cloudwalker.tar.gz 2>&1 | grep -v future"
echo "touch  cloudwalker files"
ssh centos7.1 "cd /home/cloudwalker && find . -type f -exec touch {} \;"

echo
echo "build webshell_detector"
ssh centos7.1 "cd /home/cloudwalker/php; make clean; make;cd /home/cloudwalker/bin; go build webshell_detector.go; strip -s webshell_detector" > /tmp/build-webshell.log


#源码打包
cd /home/
tar --exclude .git --exclude avira --exclude cloudwalker --exclude cppcheck --exclude pcre --exclude selftest -zcf /tmp/ngep.tar.gz ngep/

#清理上次编译残留的代码
rm -rf /home/Fish/$2/*

#使用了下面9台机器编译
#  centos5.1, centos6.0, redhat6.0, centos7.1, centos8.2, ubuntu16046, suse11.4-dev, suse12.4-dev, suse15.1-dev, ky10server
#centos5.1上会为5.0-5.11各编译一个ngep_edr.ko
#centos6.0上会为6.0-6.9各编译一个ngep_edr.ko
#centos7.1上会为7.0-7.9各编译一个ngep_edr.ko
#centos8.2上会为8.0-8.4各编译一个ngep_edr.ko
#redhat6.0上用来编译ngep程序，centos6上编的ngep在redhat6上跑，会报个库版本的警告
#suse12.4-dev上会为12.4和12.5各编译一个ngep_edr.ko
cexecs build: rm -rf /home/ngep

echo
echo "copy new antiapt to clients"
cpush build: /tmp/ngep.tar.gz /tmp/

cexec build:  "cd /home; tar -zxf /tmp/ngep.tar.gz 2>&1 | grep -v future"
echo "touch files"
cexec build:  "cd /home/ngep && find . -type f -exec touch {} \;"

echo
echo "build"
cexec build: "cd /home/ngep && time sh mk RELEASE=1" > /tmp/build-ngep.log

mkdir -p /home/Fish/$2/$1/x86_64/CentOS
mkdir -p /home/Fish/$2/$1/x86_64/RedHat/6
mkdir -p /home/Fish/$2/$1/x86_64/Ubuntu
mkdir -p /home/Fish/$2/$1/x86_64/SUSE
mkdir -p /home/Fish/$2/$1/x86_64/KylinServer
scp -r root@centos5.1:/home/ngep/dist2/* /home/Fish/$2/$1/x86_64/CentOS/         >/dev/null
scp -r root@centos6.0:/home/ngep/dist2/* /home/Fish/$2/$1/x86_64/CentOS/         >/dev/null
scp -r root@centos7.1:/home/ngep/dist2/* /home/Fish/$2/$1/x86_64/CentOS/         >/dev/null
scp -r root@centos8.2:/home/ngep/dist2/* /home/Fish/$2/$1/x86_64/CentOS/         >/dev/null
scp -r root@oraclelinux7.4:/home/ngep/dist2/* /home/Fish/$2/$1/x86_64/CentOS/    >/dev/null
scp -r root@rh60:/home/ngep/dist/*       /home/Fish/$2/$1/x86_64/RedHat/6/       >/dev/null
scp -r root@ubuntu16046:/home/ngep/dist2/*  /home/Fish/$2/$1/x86_64/Ubuntu/      >/dev/null
scp -r root@ubuntu18045:/home/ngep/dist2/*  /home/Fish/$2/$1/x86_64/Ubuntu/      >/dev/null
scp -r root@suse11.4-dev:/home/ngep/dist2/* /home/Fish/$2/$1/x86_64/SUSE/        >/dev/null
scp -r root@suse12.4-dev:/home/ngep/dist2/* /home/Fish/$2/$1/x86_64/SUSE/        >/dev/null
scp -r root@suse15.1-dev:/home/ngep/dist2/* /home/Fish/$2/$1/x86_64/SUSE/        >/dev/null
scp -r root@ky10server:/home/ngep/dist2/*   /home/Fish/$2/$1/x86_64/KylinServer/ >/dev/null

find /home/Fish/$2/$1 -type f -name ngep_location.db -exec /bin/rm {} \;

cp /home/ngep/doc/ngep_location.db /home/Fish/$2/$1/
cp /home/ngep/cert/x509.der /home/Fish/$2/$1/

cp -rf /home/ngep/external/cloudwalker/static /home/Fish/$2/$1/x86_64/
cp -rf /home/ngep/external/avira/bin /home/Fish/$2/$1/x86_64/
#cp -rf /home/ngep/external/avira/vdf /home/Fish/$2/$1/x86_64/
cp -f /home/ngep/user/lib/libiconv.so.2 /home/Fish/$2/$1/x86_64/
cp -f /home/ngep/user/lib/libsavapi.so /home/Fish/$2/$1/x86_64/
scp root@centos7.1:/home/cloudwalker/bin/webshell_detector /home/Fish/$2/$1/x86_64/

# libQt
scp root@centos5.1:/usr/lib64/qt4/lib64/libQtCore.so.4.2.1 /home/Fish/$2/$1/x86_64/CentOS/5/
scp root@centos5.1:/usr/lib64/qt4/lib64/libQtGui.so.4.2.1 /home/Fish/$2/$1/x86_64/CentOS/5/

scp root@centos6.0:/usr/lib64/libQtCore.so.4.6.2 /home/Fish/$2/$1/x86_64/CentOS/6/
scp root@centos6.0:/usr/lib64/libQtGui.so.4.6.2 /home/Fish/$2/$1/x86_64/CentOS/6/

scp root@centos7.1:/lib64/libQtCore.so.4.8.7 /home/Fish/$2/$1/x86_64/CentOS/7/
scp root@centos7.1:/lib64/libQtGui.so.4.8.7 /home/Fish/$2/$1/x86_64/CentOS/7/

scp root@centos8.2:/lib64/libQt5Core.so.5.12.5 /home/Fish/$2/$1/x86_64/CentOS/8/
scp root@centos8.2:/lib64/libQt5Gui.so.5.12.5 /home/Fish/$2/$1/x86_64/CentOS/8/
scp root@centos8.2:/lib64/libQt5Widgets.so.5.12.5 /home/Fish/$2/$1/x86_64/CentOS/8/
scp root@centos8.2:/lib64/libQt5XcbQpa.so.5.12.5 /home/Fish/$2/$1/x86_64/CentOS/8/
scp root@centos8.2:/lib64/libQt5DBus.so.5.12.5 /home/Fish/$2/$1/x86_64/CentOS/8/

scp root@centos8.2:/lib64/libxcb-icccm.so.4.0.0 /home/Fish/$2/$1/x86_64/CentOS/8/
scp root@centos8.2:/lib64/libxcb-image.so.0.0.0 /home/Fish/$2/$1/x86_64/CentOS/8/
scp root@centos8.2:/lib64/libxcb-keysyms.so.1.0.0 /home/Fish/$2/$1/x86_64/CentOS/8/
scp root@centos8.2:/lib64/libxcb-render-util.so.0.0.0 /home/Fish/$2/$1/x86_64/CentOS/8/

scp root@centos8.2:/lib64/libpcre2-16.so.0.7.1 /home/Fish/$2/$1/x86_64/CentOS/8/
scp -rq root@centos8.2:/usr/share/gnome-shell/extensions/top-icons@gnome-shell-extensions.gcampax.github.com /home/Fish/$2/$1/x86_64/CentOS/8/
scp -rq root@centos8.2:/usr/lib64/qt5/plugins/platforms/ /home/Fish/$2/$1/x86_64/CentOS/8/

scp root@ubuntu18045:/usr/lib/x86_64-linux-gnu/libQtCore.so.4.8.7 /home/Fish/$2/$1/x86_64/Ubuntu/18.04/
scp root@ubuntu18045:/usr/lib/x86_64-linux-gnu/libQtGui.so.4.8.7 /home/Fish/$2/$1/x86_64/Ubuntu/18.04/
#update install.sh
cp -f /home/ngep/tools/install.sh /home/Fish/$2/$1/
cp -f /home/ngep/tools/install.bin.head /home/Fish/$2

# make bin file

cd /home/Fish/$2
tar cf $1.tar $1
gzip $1.tar
/home/ngep/tools/build-sniper-linux.sh $1.tar.gz

grep -n ": " /tmp/build-ngep.log | grep -v -E "Leaving directory|Entering directory|stash file|, stripped| gcc |compiler"
echo "build log: /tmp/build-ngep.log"
