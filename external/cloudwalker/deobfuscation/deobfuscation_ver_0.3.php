<?php 
require __DIR__ . '/vendor/autoload.php';

use PhpParser\Error;
use PhpParser\NodeDumper;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter;
use PhpParser\Node;
use PhpParser\NodeVisitorAbstract;
use PhpParser\NodeVisitor\ParentConnectingVisitor;
use PhpParser\NodeTraverser;

//There are no more than 2 statements in one line. Return PHP code without > and <.
function preprocess($filePath){
	//get php code.
	global $linesIndex, $src;
	$file_content = file_get_contents($filePath); 
	preg_match_all('/(?!<\?=)(<\?php|<\?|<\s*script\s+language\s*=\s*"php"\s*>)([\s\S]*)(\?>|<\s*\/script\s*>|$)/Us', $file_content, $matches);
	//print_r($matches);
	$src = "";
	foreach($matches[2] as $match){
		$src.="\n".$match;
	}
	$src = str_ireplace("__FILE__", "'".$filePath."'", $src);
	//echo $src;
	//set one statement one line.
	$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
	try {
	    $ast = $parser->parse('<?php'.$src);
	} catch (Error $error) {
	    echo "Parse error: {$error->getMessage()}\n";
	    return;
	}
	$prettyPrinter = new PrettyPrinter\Standard;
	$src = $prettyPrinter->prettyPrintFile($ast);
	$src = substr($src, 5);
	
	//reparser for the function getLine(), which will be used in preprocess.
	$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
	try {
	    $ast = $parser->parse('<?php'.$src);
	} catch (Error $error) {
	    echo "Parse error: {$error->getMessage()}\n";
	    return;
	}

	$linesIndex = getlinesIndex($src);
	//preprocess.
	$preprocessTraverser = new NodeTraverser;
	$preprocessTraverser->addVisitor(new PreprocessVisitor);
	$ast= $preprocessTraverser->traverse($ast);

	$prettyPrinter = new PrettyPrinter\Standard;
	$src = $prettyPrinter->prettyPrintFile($ast);
	$src = substr($src, 5);
	//echo "\n#############\n", $src, "\n#############\n";
	return $src;
}

//This function is used to get each line's start index in src, which is the return string from function preprocess.
function getlinesIndex($src){
	$linesIndex = array(1=>0);
	$line = 2;
	for($i=0;$i<strlen($src);$i++){
		if($src[$i]=="\n"){
			$linesIndex[$line] = $i+1;
			$line += 1;
		}
	}
	return $linesIndex;
}

//This function is used to get some parts' real value from PHP interpreter. There are 4 params:
// $src : php code from function preprocess.
// $lineNumber : which line expr located in.
// $lineIndex : array from function getlinesIndex.
// $expr : the expr which you want to know its real value.
// if the return value is stored in $out, get the expr's type by $out[count($out)-2].
// if the return value is stored in $out, get the expr's type by $out[count($out)-1].
function getValueFromPHPInterpreter($src, $lineNumber, $linesIndex, $expr){
	$deobfuscationIndex = 'echo '.'"\n", '.'"deobfuscationIndexHere" '.';';

	$command = $deobfuscationIndex.'echo '.'"\n", '.'gettype('.$expr.'), '.'"\n", '.$expr.', "\n"'.';';

	$command = @substr_replace($src,$command,$linesIndex[$lineNumber],0);
	$command = str_ireplace("'", "'\''", $command);
	//echo "\n#############\n", "php -r "."'".trim($command)."'"." 2>&1", "\n#############\n";
	exec('timeout 0.7 '."php -r "."'".$command."'"." 2>&1", $out);
	//print_r($out);
	$index = array_search("deobfuscationIndexHere",$out);
	$rout=array();	
	if($index === FALSE){
		$rout[0]='null';
		$rout[1]='null';
	}
	else{
		$rout[0]=$out[$index+1];
		$rout[1]=$out[$index+2];
	}
	//echo "\n#############\n",$rout[0]," ",$rout[1], "\n#############\n";
	return $rout;
}

//This function is used to get is In FunctionDefine or ClassDefine or loop(avoid).
function isSkip(Node $node){
	$pointer = $node->getAttribute('parent');	
	while($pointer!=null){
		if(($pointer instanceof Node\Stmt\Function_) || ($pointer instanceof Node\Stmt\Class_) || $pointer instanceof Node\Stmt\While_) return true;
		$pointer = $pointer->getAttribute('parent');
	}
	return false;
}

//This function is used to get the corresponding expr of the node which will be repalced.
function getExpr(Node $node){
	$temp = new Node\Stmt\Expression($node);
	$ast = array($temp);
	$prettyPrinter = new PrettyPrinter\Standard;
	$out=$prettyPrinter->prettyPrintFile($ast);
	$out=substr($out, 5, strlen($out)-6);
	return (string)$out;
}

//This function is used to get if a funcCall has a outside arg
function isArgFromOutSide(Node $node){
	foreach ($node->args as $arg){
		if($arg->value instanceof Node\Expr\ArrayDimFetch && $arg->value->var instanceof Node\Expr\Variable && ($arg->value->var->name=='_POST' || $arg->value->var->name=='_GET' || $arg->value->var->name=='_SERVER' || $arg->value->var->name == '_FILES' || $arg->value->var->name == '_COOKIE' || $arg->value->var->name == '_SESSION' || $arg->value->var->name == '_REQUEST' || $arg->value->var->name == '_ENV')){
			return true;
		}
	}
	return false;
}

class preprocessVisitor extends NodeVisitorAbstract
{
    public function enterNode(Node $node) {
	if($node instanceof Node\Expr\ArrayDimFetch  && !isSkip($node) ){
		if($node->var instanceof Node\Expr\Variable && $node->var->name instanceof Node\Expr\Variable){
			global $src, $linesIndex;
			$out = getValueFromPHPInterpreter($src, $node->var->name->getLine(), $linesIndex, getExpr($node->var->name));	
			if(count($out)>=2){
				$type = $out[count($out)-2];
				$value = $out[count($out)-1];
				//echo "\n#############preprocess\n", "type:",$type," value:", $value, "\n#############\n";
				if($type=="string"){
					$node->var = new Node\Expr\Variable($value);
				}
			}
		}
		if($node->dim != null && !($node->dim instanceof Node\Scalar)){
			global $src, $linesIndex;
			$out = getValueFromPHPInterpreter($src, $node->dim->getLine(), $linesIndex, getExpr($node->dim));
			if(count($out)>=2){
				$type = $out[count($out)-2];
				$value = $out[count($out)-1];
				//echo "\n#############\n", "type:",$type," value:", $value, "\n#############\n";
				if($type=="string"){
					$node->dim = new Node\Scalar\String_($value);
				}
			}
		}
		
	}
    }
    public function leaveNode(Node $node){
	if($node instanceof Node\Expr\Isset_ && $node->vars[0] instanceof Node\Expr\ArrayDimFetch && ($node->vars[0]->var->name=='_POST' || $node->vars[0]->var->name=='_GET' || $node->vars[0]->var->name=='_SERVER' || $node->vars[0]->var->name == '_FILES' || $node->vars[0]->var->name == '_COOKIE' || $node->vars[0]->var->name == '_SESSION' || $node->vars[0]->var->name == '_REQUEST' || $node->vars[0]->var->name == '_ENV')){
		return new Node\Expr\ConstFetch(new Node\Name(array(true)));
	}
    }
}

//This class define the functions that changes the exprs in the ast.
class DeobfuscationVisitor extends NodeVisitorAbstract
{
    public function enterNode(Node $node) {
	if($node instanceof Node\Expr\ArrayDimFetch  && !isSkip($node) ){
		if($node->var instanceof Node\Expr\Variable && $node->var->name instanceof Node\Expr\Variable){
			global $src, $linesIndex;
			$out = getValueFromPHPInterpreter($src, $node->var->name->getLine(), $linesIndex, getExpr($node->var->name));	
			if(count($out)>=2){
				$type = $out[count($out)-2];
				$value = $out[count($out)-1];
				//echo "\n#############preprocess\n", "type:",$type," value:", $value, "\n#############\n";
				if($type=="string"){
					$node->var = new Node\Expr\Variable($value);
				}
			}
		}
		if($node->dim != null && !($node->dim instanceof Node\Scalar)){
			global $src, $linesIndex;
			$out = getValueFromPHPInterpreter($src, $node->dim->getLine(), $linesIndex, getExpr($node->dim));
			if(count($out)>=2){
				$type = $out[count($out)-2];
				$value = $out[count($out)-1];
				//echo "\n#############\n", "type:",$type," value:", $value, "\n#############\n";
				if($type=="string"){
					$node->dim = new Node\Scalar\String_($value);
				}
			}
		}
		
	}
	global $globleRec;
	if($node instanceof Node\Expr\Variable && isset($globleRec[$node->name]) && !isSkip($node)){
		$source = $globleRec[$node->name];
		$firstPart = substr($source, 0, strpos($source, '|||'));
		$secondPart = substr($source, strpos($source, '|||')+4, -1);
		return new Node\Expr\ArrayDimFetch(new Node\Expr\Variable($firstPart),new Node\Scalar\String_($secondPart));
	}
	/*
	if(($parent=$node->getAttribute('parent'))!=null) {
            if (($parent=$parent->getAttribute('parent'))!=null && ($parent instanceof Node\Stmt\Expression) && ($node instanceof Node\Expr) && !($node instanceof Node\Scalar) && !($node instanceof Node\Expr\Variable) && !($node instanceof Node\Expr\FuncCall) && !(isSkip($node))) {
			global $src, $linesIndex;
			$out = getValueFromPHPInterpreter($src, $node->getLine(), $linesIndex, getExpr($node));
			
			if(count($out)>=2){
				$type = $out[count($out)-2];
				$value = $out[count($out)-1];
				//echo "\n#############\n", "type:",$type," value:", $value, "\n#############\n";
				if($type=="string"){
					return new Node\Scalar\String_($value);
				}
				if($type=="integer"){
					return new Node\Scalar\LNumber($value);
				}
				if($type=="double"){
					return new Node\Scalar\DNumber($value); 
				}
			}

            }
        }
	*/
    }
    public function leaveNode(Node $node){
	if($node instanceof Node\Expr\FuncCall  && !isSkip($node)){
		$funcName = $node-> name;
		if($funcName instanceof Node\Expr\Variable || $funcName instanceof Node\Expr\FuncCall || $funcName instanceof Node\Expr\ArrayDimFetch){
			global $src, $linesIndex;
						
			$out = getValueFromPHPInterpreter($src, $funcName->getLine(), $linesIndex, getExpr($funcName));
			if(count($out)>=2){
				$type = $out[count($out)-2];
				$value = $out[count($out)-1];
				//echo "\n#############\n", "type:",$type," value:", $value, "\n#############\n";
				if($type=="string"){
					$node->name = new Node\Name($value);
				}
			}
		}
		for($i=0;$i<count($node->args);$i++){
			$cmp = $node->args[$i]->value;
			if(!(($cmp instanceof Node\Expr) && !($cmp instanceof Node\Scalar) && !(isSkip($cmp))))continue;	
			global $src, $linesIndex;
						
			$out = getValueFromPHPInterpreter($src, $cmp->getLine(), $linesIndex, getExpr($cmp));
			if(count($out)>=2){
				$type = $out[count($out)-2];
				$value = $out[count($out)-1];
				//echo "\n#############\n", "type:",$type," value:", $value, "\n#############\n";
				if($type=="string"){
					$node->args[$i]->value = new Node\Scalar\String_($value);
				}
				if($type=="integer"){
					$node->args[$i]->value = new Node\Scalar\LNumber($value);
				}
				if($type=="double"){
					$node->args[$i]->value = new Node\Scalar\DNumber($value); 
				}
			}
			
		}
		
	}
	if($node instanceof Node\Expr\Eval_  && !isSkip($node)){
		$code = $node->expr;
		global $src, $linesIndex;
		
		$out = getValueFromPHPInterpreter($src, $code->getLine(), $linesIndex, getExpr($code));
		if(count($out)>=2){
			$type = $out[count($out)-2];
			$value = $out[count($out)-1];
			//echo "\n#############\n", "type:",$type," value:", $value, "\n#############\n";
			if($type=="string"){
				$node->expr = new Node\Scalar\String_($value);
			}
			if($type=="integer"){
				$node->expr = new Node\Scalar\LNumber($value);
			}
			if($type=="double"){
				$node->expr = new Node\Scalar\DNumber($value); 
			}
		}
		
	}
	if($node instanceof Node\Expr\BinaryOp && (($node->left instanceof Node\Expr\ArrayDimFetch && ($node->left->var->name == '_POST' || $node->left->var->name == '_GET' || $node->left->var->name == '_SERVER'  || $node->left->var->name == '_FILES' || $node->left->var->name == '_COOKIE' || $node->left->var->name == '_SESSION' || $node->left->var->name == '_REQUEST' || $node->left->var->name == '_ENV'))||($node->right instanceof Node\Expr\ArrayDimFetch && ($node->right->var->name == '_POST' || $node->right->var->name == '_GET' || $node->right->var->name == '_SERVER' || $node->right->var->name == '_FILES' || $node->right->var->name == '_COOKIE' || $node->right->var->name == '_SESSION' || $node->right->var->name == '_REQUEST' || $node->right->var->name == '_ENV')))){
		//echo "\n#######################\n";		
		return new Node\Expr\ArrayDimFetch(new Node\Expr\Variable("_GET"), new Node\Scalar\String_("fromOutSide"));
	}
	if($node instanceof Node\Expr\Assign && $node->var instanceof Node\Expr\Variable && $node->expr instanceof Node\Expr\ArrayDimFetch && $node->expr->var instanceof Node\Expr\Variable && ($node->expr->var->name == '_POST' || $node->expr->var->name == '_GET' || $node->expr->var->name == '_SERVER' || $node->expr->var->name == '_FILES' || $node->expr->var->name == '_COOKIE' || $node->expr->var->name == '_SESSION' || $node->expr->var->name == '_REQUEST' || $node->expr->var->name == '_ENV') && !isSkip($node)){		
		global $globleRec;
		$globleValue = $node->expr->var->name.'|||';
		$globleValue.=trim(getExpr($node->expr->dim));
		if($node->var->name instanceof Node\Scalar\String_){
			$globleRec[$node->var->name->value] = $globleValue;
		}
		else{
		
			$globleRec[$node->var->name] = $globleValue;
		}
		//echo "\n############\n", $node->var->name, " ", $globleRec[$node->var->name], "\n############\n";
	}
	
	if($node instanceof Node\Expr\Assign && $node->expr instanceof Node\Expr\FuncCall && isArgFromOutSide($node->expr)){
		global $globleRec;
		$globleValue = '_GET'.'|||'.'fromOutSide';
		$globleRec[$node->var->name] = $globleValue;
	}
	
    }
    /*
    public function leaveNode(Node $node) {
		
        if (($parent=$node->getAttribute('parent'))!=null) {
	    if(($parent instanceof Node\Stmt) && ($node instanceof Node\Expr\FuncCall)){
			foreach ($node->args as $arg){
				$tnode = $arg->value;
				if(!(($tnode instanceof Node\Expr) && !($tnode instanceof Node\Scalar) && !($tnode instanceof Node\Expr\Variable)))continue;
				// here are exprs in function args.
				echo $tnode->getType(), " ", $tnode->getLine(),"\n";
			}
	    }

            if (($parent=$parent->getAttribute('parent'))!=null && (($parent instanceof Node\Stmt)||($parent instanceof Node\Stmt\Expression)) && ($node instanceof Node\Expr) && !($node instanceof Node\Scalar) && !($node instanceof Node\Expr\Variable)) {
			// here are exprs in statements
			echo $node->getType(), " ", $node->getLine(),"\n";


            }
        }
    }
    */
}

function deobfuscation($filePath){
	global $src, $globalRec, $linesIndex;
	$src = preprocess($filePath);
	$globleRec = array();
	$linesIndex = getlinesIndex($src);

	$parser = (new ParserFactory)->create(ParserFactory::PREFER_PHP7);
	try {
	    $ast = $parser->parse('<?php'.$src);
	} catch (Error $error) {
	    echo "Parse error: {$error->getMessage()}\n";
	    return;
	}

	$dumper = new NodeDumper;
	$traverser = new NodeTraverser;
	$traverser->addVisitor(new ParentConnectingVisitor);
	$ast    = $traverser->traverse($ast);

	//echo $dumper->dump($ast) . "\n";
	$myTraverser = new NodeTraverser;
	$myTraverser->addVisitor(new DeobfuscationVisitor);
	$ast= $myTraverser->traverse($ast);
	//echo $dumper->dump($ast) . "\n";

	$prettyPrinter = new PrettyPrinter\Standard;
	return $prettyPrinter->prettyPrintFile($ast);
}

//echo deobfuscation("./fortest.php");

if($argc==2){
	echo deobfuscation($argv[1]);
}


?>
