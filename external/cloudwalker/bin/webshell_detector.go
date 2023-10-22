package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"C"

	"../php"
	"../src"
)

var outputPtr *string
var htmlPtr *bool
var detector *WebshellDetector.Detector
var countRisk = 0
var countRisk1 = 0
var countRisk2 = 0
var countRisk3 = 0
var countRisk4 = 0
var countRisk5 = 0
var countFile = 0
var t0 = time.Now()
var err error

func walk(path string, info os.FileInfo, _ error) error {

	countFile++

	if strings.ToLower(filepath.Ext(path)) != ".php" &&
		strings.ToLower(filepath.Ext(path)) != ".phpt" &&
		strings.ToLower(filepath.Ext(path)) != ".php3" &&
		strings.ToLower(filepath.Ext(path)) != ".php4" &&
		strings.ToLower(filepath.Ext(path)) != ".php5" &&
		strings.ToLower(filepath.Ext(path)) != ".txt" &&
		strings.ToLower(filepath.Ext(path)) != ".bak" {
		return nil
	}
	src, err := ioutil.ReadFile(path)
	if err != nil {
//		log.Fatal(err)
		return err
	}
	dsrc := WebshellDetector.Deobfuscation(path)
	score :=0
	if dsrc == nil {
		score, err = detector.Predict(src)
	}else{
		score, err = detector.PredictWithDeobfuscation(src,dsrc)
	}
	
	// if err != nil {
	// 	log.Fatal(err)
	// }
	for i := 0; i < 128; i++ {
		fmt.Printf("\b")
	}
	fmt.Printf("\rTesting %-50s / %d risks / Runtime %v", info.Name(), countRisk, time.Since(t0))
	if score > 0 {
		countRisk++
		var risk int
		switch score {
		case 1, 2:
			risk = 1
			countRisk1++
		case 3:
			risk = 2
			countRisk2++
		case 4:
			risk = 3
			countRisk3++
		case 5:
			risk = 4
			countRisk4++
		case 6, 7:
			risk = 5
			countRisk5++
		default:
			risk = 0
		}
		printResult(countFile, path, risk)
	}
	return nil
}

func multiTest(detectPath string) {
	if err != nil {
//		log.Fatal(err)
		return
	}
	filepath.Walk(detectPath, walk)
}

func singleTest(path string) int {
	if err != nil {
//		log.Fatal(err)
		return -1
	}
	src, err := ioutil.ReadFile(path)
	if err != nil {
//		log.Fatal(err)
		return -1
	}
	dsrc := WebshellDetector.Deobfuscation(path)
	score :=0
	if dsrc == nil {
		score, err = detector.Predict(src)
		if err != nil {
//			log.Fatal(err)
			return -1
		}
	}else{
		score, err = detector.PredictWithDeobfuscation(src,dsrc)
		if err != nil {
//			log.Fatal(err)
			return -1
		}
	}
	return score
}

func printResult(fileIndex int, filePath string, fileRisk int) {
	var res string
	if len(filePath) > 80 && !*htmlPtr {
		filePath = "..." + filePath[len(filePath)-77:len(filePath)]
	}
	if *htmlPtr {
		res = fmt.Sprintf("<tr><td>%08d<td>%s<td>%d\n", fileIndex, filePath, fileRisk)
	} else {
		res = fmt.Sprintf("[+] %08d %-80s Risk:%d\n", fileIndex, filePath, fileRisk)
	}
	if *outputPtr != "" {
		outputFile, err := os.OpenFile(*outputPtr, os.O_WRONLY|os.O_APPEND, os.ModePerm)
		if err != nil {
//			log.Fatal(err)
			return
		}
		outputFile.WriteString(res)
		outputFile.Close()
	} else {
		for i := 0; i < 128; i++ {
			fmt.Printf("\b")
		}
		fmt.Print(res)
	}
}

func work(files []string) int {
	var risk int
	for _, v := range files {
		info, err := os.Stat(v)
		if err != nil {
			return -1
		}
		if info.IsDir() {
			return -1;
		} else {
			risk = singleTest(v)
		}
	}
	return risk
}

func main() {
	var risk int

	flag.Parse()
	if len(flag.Args()) == 0 {
		log.Println("-1");
	}

	files := flag.Args()
	php.Start()
	detector, err = WebshellDetector.NewDefaultDetector(php.Stdin, php.Stdout)
	if err != nil {
		log.Println("-1")
	}

	risk = work(files)
	fmt.Println(risk)
}
