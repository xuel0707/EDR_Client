if [ ! -d oem ]
then
        echo "run sh oem/ksedr/oem_ksedr.sh under source directory"
        exit
fi

#logo
cp oem/ksedr/ksedr.png qt/logo/sniper.png
#版本信息
cp oem/ksedr/vendor_ksedr.h include/vendor_sniper.h
#打包脚本
cp tools/ngep-release-centos-ub16046-suse.sh tools/ksedr-release-centos-ub16046-suse.sh
sed -i "s/ngep/ksedr/g" tools/ksedr-release-centos-ub16046-suse.sh
sed -i "s/Ngep/Ksedr/g" tools/ksedr-release-centos-ub16046-suse.sh
sed -i "s/NGEP/KSEDR/g" tools/ksedr-release-centos-ub16046-suse.sh

#在7.111上接着做下面的命令，注意修改版本号
#cd; sh -x /home/ksedr/tools/ksedr-release-centos-ub16046-suse.sh ksedr-linux-5.0.3.1105 oem
