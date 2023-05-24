#!/bin/bash

if [ $# -ne 1 ]
then
	echo "Usage: $0 sniper-linux-W.X.Y.Z.tar.gz"
	exit
fi

pkg=$1
filename=`basename $pkg | sed "s/[0-9]//g"`

if [ "$filename" != "sniper-linux-....tar.gz" ]
then
	echo "Usage: $0 sniper-linux-W.X.Y.Z.tar.gz"
	exit
fi

# 取当前版本: sniper-linux-W.X.Y.Z
sniperver=`basename $pkg | sed "s/\.tar\.gz//g"`
svhead=`echo $sniperver | cut -f1-2 -d"-"`
if [ "$svhead" != "sniper-linux" ]
then
	echo "Usage: $0 sniper-linux-W.X.Y.Z.tar.gz"
	exit
fi

LOG="/var/log/sniper-install.log"
MYBIN=$sniperver.bin

# 蓝海星带上LHX标识，以与原生sniper区别
LHX=0
if [ $LHX -eq 1 ]
then
	MYBIN=`echo $MYBIN | sed "s/sniper/sniperLHX/g"`
fi

size=`wc -c install.bin.head | awk '{print $1}'`
if [ $size -ge 4096 ]
then
	echo "Size of install.bin.head should not exceed 4096 bytes"
	exit
fi

# 生成自解压安装程序头
cat install.bin.head | sed "s/SNIPERVER/$sniperver/g" > $MYBIN

# 将真正的安装包附加在自解压程序的尾部
dd if=$pkg of=$MYBIN bs=4096 seek=1 >/dev/null 2>&1

chmod u+x $MYBIN
echo "Install binary package is `pwd`/$MYBIN"
