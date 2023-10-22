if [ ! -d oem ]
then
        echo "run sh oem/sedr/oem_sedr.sh under source directory"
        exit
fi

#logo
cp oem/sedr/sedr.png qt/logo/sniper.png
#版本信息
cp oem/sedr/vendor_sedr.h include/vendor_sniper.h
#打包脚本
cp tools/ngep-release-centos-ub16046-suse.sh tools/sedr-release-centos-ub16046-suse.sh
sed -i "s/ngep/sedr/g" tools/sedr-release-centos-ub16046-suse.sh
sed -i "s/Ngep/Sedr/g" tools/sedr-release-centos-ub16046-suse.sh
sed -i "s/NGEP/SEDR/g" tools/sedr-release-centos-ub16046-suse.sh

#在7.111上接着做下面的命令，注意修改版本号
#cd; sh -x /home/sedr/tools/sedr-release-centos-ub16046-suse.sh sedr-linux-5.0.3.1105 oem
