if [ ! -d oem ]
then
        echo "run sh oem/ecguard/oem_ecguard.sh under source directory"
        exit
fi

#logo
cp oem/ecguard/ecguard.png qt/logo/sniper.png
#版本信息
cp oem/ecguard/vendor_ecguard.h include/vendor_sniper.h
#打包脚本
cp tools/ngep-release-centos-ub16046-suse.sh tools/ecguard-release-centos-ub16046-suse.sh
sed -i "s/ngep/ecguard/g" tools/ecguard-release-centos-ub16046-suse.sh
sed -i "s/Ngep/ecGuard/g" tools/ecguard-release-centos-ub16046-suse.sh
sed -i "s/NGEP/ECGUARD/g" tools/ecguard-release-centos-ub16046-suse.sh

#在7.111上接着做下面的命令，注意修改版本号
#cd; sh -x /home/ecguard/tools/ecguard-release-centos-ub16046-suse.sh ecguard-linux-2.0.5.220121 ecguard
