#!/bin/bash -x
# 用法：sh make-ngep_antivirus-zip.sh ngep-linux-5.0.9.220606 regular anti-5.0.9.0708-linux

# 执行完ngep-release-centos-ub16046-suse.sh成功之后再执行，
# ngep-linux-5.0.9.220606和regular两个参数分别对应执行ngep-release-centos-ub16046-suse.sh时后面填的两个参数

# 创建目录
mkdir -p /home/Fish/$2/$3/x86_64/CentOS/{6,7,8}
mkdir -p /home/Fish/$2/$3/x86_64/RedHat/6
mkdir -p /home/Fish/$2/$3/x86_64/Ubuntu/16.04
mkdir -p /home/Fish/$2/$3/x86_64/KylinServer/10

#centos5,redhat5和suse不支持编译ngep_antivirus, ubuntu只有16.04支持
#拷贝编译好的ngep_antivirus
cp -f /home/Fish/$2/$1/x86_64/CentOS/6/ngep_antivirus /home/Fish/$2/$3/x86_64/CentOS/6/
cp -f /home/Fish/$2/$1/x86_64/CentOS/7/ngep_antivirus /home/Fish/$2/$3/x86_64/CentOS/7/
cp -f /home/Fish/$2/$1/x86_64/CentOS/8/ngep_antivirus /home/Fish/$2/$3/x86_64/CentOS/8/

cp -f /home/Fish/$2/$1/x86_64/RedHat/6/ngep_antivirus /home/Fish/$2/$3/x86_64/RedHat/6/

cp -f /home/Fish/$2/$1/x86_64/Ubuntu/16.04/ngep_antivirus /home/Fish/$2/$3/x86_64/Ubuntu/16.04/

cp -f /home/Fish/$2/$1/x86_64/KylinServer/10/ngep_antivirus /home/Fish/$2/$3/x86_64/KylinServer/10/

#打包
cd /home/Fish/$2/ 
zip -r $3.zip $3/

#清除目录，方便下次拷贝压缩
rm -rf /home/Fish/$2/$3/
