package main

import (
	"bufio"
	"io"
	"io/ioutil"
	"github.com/glaslos/ssdeep"
	"bytes"
	"os"
	"fmt"
)

type sampleMatcher struct {
	hashes []string
}

func newSampleMatcher(sampleHashFile io.Reader) (*sampleMatcher, error) {

	matcher := sampleMatcher{nil}
	reader := bufio.NewReader(sampleHashFile)
	for line, _, err := reader.ReadLine(); err == nil; line, _, err = reader.ReadLine() {
		matcher.hashes = append(matcher.hashes, string(line))
	}

	return &matcher, nil
}

func (matcher *sampleMatcher) Match(src []byte) (bool, string, error) {
	hash, err := ssdeep.FuzzyBytes(src)
	if err != nil {
		return false, hash, err
	}
	for _, h := range matcher.hashes {
		score, err := ssdeep.Distance(hash, h)
		if err != nil {
			return false, hash, err
		}
		if score > 90 {
			return true, hash, nil
		}
	}

	return false, hash, nil
}

func checkFileIsExist(filename string) bool {
	var exist = true
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		exist = false
	}
	return exist
}

func main(){
	path := ""
	if len(os.Args)>1 {
		path = os.Args[1]
	}else{
		fmt.Println("Add Hash: add failed. please input file path")
		return
	}
	src, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
		return
	}

	sampleMatcherStream, err := ioutil.ReadFile("static/model-latest/SampleHash.txt")
	if err != nil {
		fmt.Println("Add Hash: add failed. read SampleHash.txt failed")
		return
	}
	sampleMatcherStreamReader := bytes.NewReader(sampleMatcherStream)
	if err != nil {
		fmt.Println("Add Hash: add failed. read SampleHash.txt failed")
		return
	}
	sampleMatcher, err := newSampleMatcher(sampleMatcherStreamReader)
	if err != nil {
		fmt.Println("Add Hash: add failed. read SampleHash.txt failed")
		return
	}

	isMatched, hash, err := sampleMatcher.Match(src)
	if err != nil {
		fmt.Println(err)
		return
	}
	if isMatched {
		fmt.Println("Add Hash: add failed. sample has already added before")
		return
	} else{	
		f, err := os.OpenFile("static/model-latest/SampleHash.txt", os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println(err)
	 
		} else {
			content := hash + "\n"
			n, _ := f.Seek(0, 2)
			_, err = f.WriteAt([]byte(content), n)
		}
 
		defer f.Close()
		fmt.Println("Add Hash: add successfully!")
	}
}
