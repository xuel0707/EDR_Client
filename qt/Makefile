all: snipertray sniper_showlog sniper_strategy sniper_status sniper_docrestore sniper_hostinfo sniper_uninstall sniper_force_uninstall sniper_servaddr
	@mkdir -p ./dist/
	@cp logo/snipertray.desktop logo/sniper.png logo/sniper-server-setting.desktop ./dist/
	@cp tray/snipertray ./dist/
	@cp showlog/sniper_showlog ./dist/
	@cp strategy/sniper_strategy ./dist/
	@cp status/sniper_status ./dist/
	@cp docrestore/sniper_docrestore ./dist/
	@cp hostinfo/sniper_hostinfo ./dist/
	@cp uninstall/sniper_uninstall ./dist/
	@cp force_uninstall/sniper_force_uninstall ./dist/
	@cp servaddr/sniper_servaddr ./dist/
	@strip -s ./dist/snipertray ./dist/sniper_*

snipertray:
	@sh mk tray

sniper_showlog:
	@sh mk showlog

sniper_strategy:
	@sh mk strategy

sniper_status:
	@sh mk status

sniper_docrestore:
	@sh mk docrestore

sniper_hostinfo:
	@sh mk hostinfo

sniper_uninstall:
	@sh mk uninstall

sniper_force_uninstall:
	@sh mk force_uninstall

sniper_servaddr:
	@sh mk servaddr

clean:
	@sh mk clean
