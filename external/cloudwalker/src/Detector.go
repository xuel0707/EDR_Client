package WebshellDetector

import (
//	"log"

	"github.com/CyrusF/go-bayesian"
	"github.com/CyrusF/libsvm-go"
	//"fmt"
	"bytes"
	"os"
	"regexp"
	"io/ioutil"

	"github.com/glaslos/ssdeep"
)

/*
WebshellDetector - Refactor version 1
Date	0814
Author	Cyrus, Twice
Intro	Read model from file
        Give an interface for predict
*/

type DetectorConfig struct {
	modelPath          string
	configPath         string
	enableProcessor    bool
	enableRegMatcher   bool
	enableSampleMather bool
	enableStatCheck    bool
}

func NewDetectorConfig() (*DetectorConfig, error) {
	return &DetectorConfig{"", "", true, true, true, true}, nil
}

type Detector struct {
	opSerialModel *libSvm.Model
	processModel  *libSvm.Model
	wordsModel    *bayesian.Classifier
	regMatcher    *regMatcher
	sampleMatcher *sampleMatcher
	hashState     arrayHashState
	statState     arrayStatState
	stdin         *os.File
	stdout        *os.File
	config        *DetectorConfig
}

func NewDetectorWithConfig(config *DetectorConfig, opSerialStream []byte, processorStream []byte, wordStream []byte, hashStateBytes []byte, statStateBytes []byte, regMatcherStream []byte, sampleMatcherStream []byte, stdin *os.File, stdout *os.File) (*Detector, error) {
	var self Detector
	var err error

	self.config = config
	opSerialStreamReader := bytes.NewReader(opSerialStream)
	self.opSerialModel = libSvm.NewModelFromFileStream(opSerialStreamReader)
	processorStreamReader := bytes.NewReader(processorStream)
	self.processModel = libSvm.NewModelFromFileStream(processorStreamReader)

	wordStreamReader := bytes.NewReader(wordStream)
	tmpWordsModel, _ := bayesian.NewClassifierFromFileStream(wordStreamReader)
	self.wordsModel = &tmpWordsModel // make all struct element to be pointer

	self.hashState = newArrayHashState()
	self.hashState.Load(hashStateBytes)

	self.statState = newArrayStatState()
	err = self.statState.Load(statStateBytes)
	if err != nil {
		return nil, err
	}

	regMatcherStreamReader := bytes.NewReader(regMatcherStream)
	self.regMatcher, err = newRegMatcher(regMatcherStreamReader)
	if err != nil {
		return nil, err
	}

	sampleMatcherStreamReader := bytes.NewReader(sampleMatcherStream)
	self.sampleMatcher, err = newSampleMatcher(sampleMatcherStreamReader)
	if err != nil {
		return nil, err
	}

	self.stdin = stdin
	self.stdout = stdout
	return &self, nil
}

func NewDetector(opSerialStream []byte, processorStream []byte, wordStream []byte, hashStateBytes []byte, statStateBytes []byte, regMatcherStream []byte, sampleMatcherStream []byte, stdin *os.File, stdout *os.File) (*Detector, error) {
	if config, err := NewDetectorConfig(); err == nil {
		return NewDetectorWithConfig(config, opSerialStream, processorStream, wordStream, hashStateBytes, statStateBytes, regMatcherStream, sampleMatcherStream, stdin, stdout)
	} else {
		return nil, err
	}
}

func NewDefaultDetector(stdin *os.File, stdout *os.File) (*Detector, error) {
	opSerialStream, err := Asset("/opt/snipercli/static/model-latest/OpSerial.model")
	if err != nil {
//		log.Fatal(err)
		return nil, err
	}
	processorStream, err := Asset("/opt/snipercli/static/model-latest/Processor.model")
	if err != nil {
//		log.Fatal(err)
		return nil, err
	}
	wordStream, err := Asset("/opt/snipercli/static/model-latest/Words.model")
	if err != nil {
//		log.Fatal(err)
		return nil, err
	}
	hashStateBytes, err := Asset("/opt/snipercli/static/model-latest/hashState.json")
	if err != nil {
//		log.Fatal(err)
		return nil, err
	}
	statStateBytes, err := Asset("/opt/snipercli/static/config/statState.json")
	if err != nil {
//		log.Fatal(err)
		return nil, err
	}
	regMatcherStream, err := Asset("/opt/snipercli/static/config/rules.conf")
	if err != nil {
//		log.Fatal(err)
		return nil, err
	}
	/*
	sampleMatcherStream, err := Asset("/opt/snipercli/static/model-latest/SampleHash.txt")
	f, err := ioutil.ReadFile("/opt/snipercli/static/model-latest/SampleHash.txt")
	fmt.Println(reflect.TypeOf(sampleMatcherStream)) 
	fmt.Println(reflect.TypeOf(f)) 
	fmt.Println(len(sampleMatcherStream)) 
	fmt.Println(len(f)) 
	same := true	
	for i:=0;i<len(sampleMatcherStream);i++ {
		if sampleMatcherStream[i] != f[i]{
			same = false
		}
	}
	fmt.Println(same)
	*/
	sampleMatcherStream, err := ioutil.ReadFile("/opt/snipercli/static/model-latest/SampleHash.txt")
	if err != nil {
//		log.Fatal(err)
		return nil, err
	}
	
	return NewDetector(opSerialStream, processorStream, wordStream, hashStateBytes, statStateBytes, regMatcherStream, sampleMatcherStream, stdin, stdout)
}

func (self Detector) Predict(src []byte) (int, error) {
	isPhpCode := func(src []byte) bool {
		return bytes.Contains(src, []byte("<?")) || regexp.MustCompile(`<script\s+language\s*=\s*["']php["']\s*>`).Match(src)
	}

	var err error

	processor, err := newProcessorFromSrc(&self, src, self.stdin, self.stdout)
	if err != nil {
		return -999, err
	}

	if !isPhpCode(src) {
		return -1, nil
	}

	result := 0

	/* 正则检测 */
	if self.config.enableRegMatcher && self.regMatcher.IsMatched(src) > 0 {
		result += 1
	}

	/* 基于统计 */
	if self.config.enableStatCheck && processor.stat.IsAbnormal(self.statState) && processor.callable {
		result += 10
	}

	isMatchedBySample := false
	if self.config.enableSampleMather {
		isMatchedBySample, err = self.sampleMatcher.Match(src)
		if err != nil && err != ssdeep.ErrFileTooSmall {
			return -1, err
		}
	}

	/* 模糊哈希 */
	if (self.config.enableSampleMather && isMatchedBySample) {
		result += 100
	}

	/* 机器学习 */	
	if (self.config.enableProcessor && processor.Predict() < 0) {		
		result += 1000
	}	

	return result, nil
}

func (self Detector) PredictWithDeobfuscation(src []byte, dsrc []byte) (int, error) {
	isPhpCode := func(src []byte) bool {
		return bytes.Contains(src, []byte("<?")) || regexp.MustCompile(`<script\s+language\s*=\s*["']php["']\s*>`).Match(src)
	}

	var err error

	processor, err := newProcessorFromSrc(&self, src, self.stdin, self.stdout)
	if err != nil {
		return -999, err
	}

	if !isPhpCode(src) {
		return -1, nil
	}

	result := 0

	/* 正则检测 */
	if self.config.enableRegMatcher && ((self.regMatcher.IsMatched(src)>0) || (self.regMatcher.IsMatched(dsrc)> 0)) {
		result += 1
	}

	/* 基于统计 */
	if self.config.enableStatCheck && processor.stat.IsAbnormal(self.statState) && processor.callable {
		result += 10
	}

	isMatchedBySample := false
	isMatchedBySampleAfterDeobfuscation := false
	if self.config.enableSampleMather {
		isMatchedBySample, err = self.sampleMatcher.Match(src)
		if err != nil && err != ssdeep.ErrFileTooSmall {
			return -1, err
		}
		isMatchedBySampleAfterDeobfuscation, err = self.sampleMatcher.Match(dsrc)
		if err != nil && err != ssdeep.ErrFileTooSmall {
			return -1, err
		}
	}

	/* 模糊哈希 */
	if (self.config.enableSampleMather && (isMatchedBySample || isMatchedBySampleAfterDeobfuscation)) {
		result += 100
	}

	/* 机器学习 */	
	if (self.config.enableProcessor && processor.Predict() < 0) {
		result += 1000
	}

	return result, nil
} 

