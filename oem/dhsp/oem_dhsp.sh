if [ ! -d oem ]
then
        echo "run sh oem/dhsp/oem_dhsp.sh under source directory"
        exit
fi

#logo
cp oem/dhsp/dhsp.png qt/logo/sniper.png
#版本信息
cp oem/dhsp/vendor_dhsp.h include/vendor_sniper.h
#打包脚本
cp tools/ngep-release-centos-ub16046-suse.sh tools/dhsp-release-centos-ub16046-suse.sh
sed -i "s/ngep/dhsp/g" tools/dhsp-release-centos-ub16046-suse.sh
sed -i "s/Ngep/Dhsp/g" tools/dhsp-release-centos-ub16046-suse.sh
sed -i "s/NGEP/DHSP/g" tools/dhsp-release-centos-ub16046-suse.sh

#在7.111上接着做下面的命令，注意修改版本号
#cd; sh -x /home/dhsp/tools/dhsp-release-centos-ub16046-suse.sh dhsp-linux-5.0.3.1105 oem
