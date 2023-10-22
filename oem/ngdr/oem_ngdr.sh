if [ ! -d oem ]
then
        echo "run sh oem/ngdr/oem_ngdr.sh under source directory"
        exit
fi

#logo
cp oem/ngdr/ngdr.png qt/logo/sniper.png
#版本信息
cp oem/ngdr/vendor_ngdr.h include/vendor_sniper.h
#打包脚本
cp tools/ngep-release-centos-ub16046-suse.sh tools/ngdr-release-centos-ub16046-suse.sh
sed -i "s/ngep/ngdr/g" tools/ngdr-release-centos-ub16046-suse.sh
sed -i "s/Ngep/Ngdr/g" tools/ngdr-release-centos-ub16046-suse.sh
sed -i "s/NGEP/NGDR/g" tools/ngdr-release-centos-ub16046-suse.sh

#在7.111上接着做下面的命令，注意修改版本号
#cd; sh -x /home/ngdr/tools/ngdr-release-centos-ub16046-suse.sh ngdr-linux-2.0.5.220121 ngdr
