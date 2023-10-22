cd /tmp/ngep-arm64
rm -f */*/*/ngep_location.db
rm -f ngep-linux-*.bin ngep-linux-*.tar.gz

pkgname=`ls -d ngep-linux-*`
if [ "$pkgname" = "" ]; then
	echo "no package direcotry ngep-linux-..."
	exit
fi

tar zcf $pkgname.tar.gz $pkgname
sh build-ngep-linux.sh $pkgname.tar.gz
if [ -f $pkgname.bin ]; then
	mv $pkgname.bin $pkgname.aarch64.bin
	echo "rename to /tmp/ngep-arm64/$pkgname.aarch64.bin"
fi
