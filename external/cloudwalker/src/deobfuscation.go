package WebshellDetector

import (
    "io/ioutil"
    "os/exec"
)

func Deobfuscation(filePath string) ([]byte){
    cmd := exec.Command("php", "../deobfuscation/deobfuscation_ver_0.3.php", filePath)

    stdout, _ := cmd.StdoutPipe()

    if err := cmd.Start(); err != nil{
        return nil
    }

    out_bytes, _ := ioutil.ReadAll(stdout)
    stdout.Close()

    if err := cmd.Wait(); err != nil {
        return nil
    }
    
    
    if string(out_bytes)[0:5] != "<?php" {
	return nil
    }    

    return []byte(out_bytes)
}
