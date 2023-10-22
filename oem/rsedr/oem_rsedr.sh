if [ ! -d oem ]
then
        echo "run sh oem/rsedr/oem_rsedr.sh under source directory"
        exit
fi

#logo
cp oem/rsedr/rsedr.png qt/logo/sniper.png
#版本信息
cp oem/rsedr/vendor_rsedr.h include/vendor_sniper.h
#打包脚本
cp tools/ngep-release-centos-ub16046-suse.sh tools/rsedr-release-centos-ub16046-suse.sh
sed -i "s/ngep/rsedr/g" tools/rsedr-release-centos-ub16046-suse.sh
sed -i "s/Ngep/Rsedr/g" tools/rsedr-release-centos-ub16046-suse.sh
sed -i "s/NGEP/RSEDR/g" tools/rsedr-release-centos-ub16046-suse.sh

#在7.111上接着做下面的命令，注意修改版本号
#cd; sh -x /home/rsedr/tools/rsedr-release-centos-ub16046-suse.sh rsedr-linux-5.0.3.1105 oem
