test_mbr()
{
	echo
	echo "== Mbr Test =="

	#事件

	#非事件

}

test_mbr_root()
{
	echo
	echo "== Mbr Test =="

	#事件
	swapdev=`swapon -s | grep dev | awk '{print $1}'`
	if [ "$swapdev" = "" ]
	then
		echo "no swap device, skip test"
	else
		swapoff -a
		dd if=$swapdev of=/tmp/mbr.disk bs=512 count=1
		dd if=/tmp/mbr.disk of=$swapdev bs=512 count=1

		dd if=$swapdev of=/tmp/mbr.disk2 bs=512 count=1
		dd if=/tmp/mbr.disk2 of=$swapdev bs=512 count=1
		swapon -a
	fi

	#非事件

}

test_mbr_clean()
{
	echo "== Mbr Test Clean =="

}
