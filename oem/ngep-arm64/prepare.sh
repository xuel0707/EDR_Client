if [ $# -ne 1 ]; then
	echo "Usage: sh prepare.sh PACKAGE-NAME"
	echo "  exp. sh prepare.sh ngep-linux-5.0.4.211201"
	exit
fi

#删除老的打包目录
WORKDIR="/tmp/ngep-arm64"
rm -rf $WORKDIR

#创建打包目录
mkdir -p $WORKDIR/$1/KylinServer/
mkdir -p $WORKDIR/$1/KylinDesktop/

#拷贝打包脚本文件
cp ../../tools/build-sniper-linux.sh $WORKDIR/build-ngep-linux.sh
cp ../../tools/install.bin.head $WORKDIR
cp ../../tools/install.sh $WORKDIR/$1/

#替换产品名关键字
find $WORKDIR -path ./.git -prune -o -path ./oem -prune -o -type f -exec sed -i "s/sniper/ngep/g" "{}" \;
find $WORKDIR -path ./.git -prune -o -path ./oem -prune -o -type f -exec sed -i "s/Sniper/NGEP/g" "{}" \;
find $WORKDIR -path ./.git -prune -o -path ./oem -prune -o -type f -exec sed -i "s/SNIPER/NGEP/g" "{}" \;

#拷贝ip地址库
cp ../../doc/sniper_location.db $WORKDIR/$1/ngep_location.db
