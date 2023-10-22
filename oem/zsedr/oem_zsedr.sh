if [ ! -d oem ]
then
        echo "run sh oem/zsedr/oem_zsedr.sh under source directory"
        exit
fi

#logo
cp oem/zsedr/zsedr.png qt/logo/sniper.png
#版本信息
cp oem/zsedr/vendor_zsedr.h include/vendor_sniper.h
#打包脚本
cp tools/ngep-release-centos-ub16046-suse.sh tools/zsedr-release-centos-ub16046-suse.sh
sed -i "s/ngep/zsedr/g" tools/zsedr-release-centos-ub16046-suse.sh
sed -i "s/Ngep/Zsedr/g" tools/zsedr-release-centos-ub16046-suse.sh
sed -i "s/NGEP/ZSEDR/g" tools/zsedr-release-centos-ub16046-suse.sh

#在7.111上接着做下面的命令，注意修改版本号
#cd; sh -x /home/zsedr/tools/zsedr-release-centos-ub16046-suse.sh zsedr-linux-5.0.3.1105 oem
