find . -type f -exec touch {} \;
make clean
cp -f include/vendor_sniper.h include/vendor_ngep.h
cp -f qt/logo/sniper-server-setting.desktop qt/logo/ngep-server-setting.desktop
cp -f qt/logo/snipertray.desktop qt/logo/ngeptray.desktop
cp -f qt/logo/sniper.png qt/logo/ngep.png
cp -f tools/sniper_cron tools/ngep_cron
cp -f tools/sniper_chk tools/ngep_chk
cp -f tools/assist_sniper_chk tools/assist_ngep_chk
cp -f check_sniper_strip check_ngep_strip
cp -f doc/sniper_location.db doc/ngep_location.db
cp -rf deb/sniper deb/ngep

cp -f oem/ngep-arm64/libpcre.a user/libpcre.a

find ./ -path ./.git -prune -o -path ./oem -prune -o -type f -exec sed -i "s/sniper/ngep/g" "{}" \;
find ./ -path ./.git -prune -o -path ./oem -prune -o -type f -exec sed -i "s/Sniper/NGEP/g" "{}" \;
find ./ -path ./.git -prune -o -path ./oem -prune -o -type f -exec sed -i "s/SNIPER/NGEP/g" "{}" \;
