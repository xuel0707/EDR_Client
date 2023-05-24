test_blacklist()
{
	echo "== Blacklist Test =="

	gcc -o black black.c

	#用于测试黑名单程序简单地在尾部添加内容不能逃逸md5检测
	cp black black.var
	echo "1234567890" >> black.var

	#用于测试黑名单程序改名不能逃逸md5检测
	cp -f black kcalb

	md5sum black
	./black 123
	#用于测试黑名单程序对命令行的匹配
	./black 456

	md5sum black.var
	./black.var 123
	./black.var 123456

	md5sum kcalb
	./kcalb 123
	./kcalb 123 456
}

test_blacklist_clean()
{
	echo "== Blacklist Test Clean =="
}
