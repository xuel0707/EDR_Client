if [ ! -d oem ]
then
        echo "run sh oem/sca/oem_sca.sh under source directory"
        exit
fi

#logo
cp oem/sca/sca.png qt/logo/sniper.png
#版本信息
cp oem/sca/vendor_sca.h include/vendor_sniper.h
#打包脚本
cp tools/ngep-release-centos-ub16046-suse.sh tools/sca-release-centos-ub16046-suse.sh
sed -i "s/ngep/sca/g" tools/sca-release-centos-ub16046-suse.sh
sed -i "s/Ngep/Sca/g" tools/sca-release-centos-ub16046-suse.sh
sed -i "s/NGEP/SCA/g" tools/sca-release-centos-ub16046-suse.sh

#在7.111上接着做下面的命令，注意修改版本号
#cd; sh -x /home/sca/tools/sca-release-centos-ub16046-suse.sh sca-linux-2.0.5.220121 sca
