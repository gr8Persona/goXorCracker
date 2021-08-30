package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"time"
)

type Result struct {
	Found bool
	Key   string
	Data  []byte
}

func main() {
	inPtr := flag.String("in", "", "input file path")
	wlPtr := flag.String("w", "", "wordlist file path")
	keyPtr := flag.String("key", "", "password")
	encryptPtr := flag.Bool("encrypt", false, "encrypt file")
	decryptPtr := flag.Bool("decrypt", false, "decrypt file")
	crackPtr := flag.Bool("crack", false, "crack the password by using wordlist (use -w key for file path)")
	regexPtr := flag.String("regex", "(?i)\\b(cipher|plaintext|information|alice)", "GOLANG regex for known data search in decoded ASCII data")
	crackThreadsPtr := flag.Int("t", 4, "threads for cracking")
	flag.Parse()

	data, err := readFile(*inPtr)
	if err != nil {
		showErr(err)
	}
	if !*encryptPtr && !*decryptPtr && !*crackPtr {
		showErr(fmt.Errorf("you have to select one of following keys: -encrypt / -decrypt / -crack"))
	}
	if *encryptPtr {
		out := encrypt(data, *keyPtr)
		fmt.Printf(out)
	} else if *decryptPtr {
		out, err := decrypt(data, *keyPtr)
		if err != nil {
			showErr(err)
		}
		fmt.Printf("%s", out)
	} else if *crackPtr {
		rFind := regexp.MustCompile(*regexPtr)
		if err := crackWordlistThreaded(data, *wlPtr, *crackThreadsPtr, rFind, 10); err != nil {
			showErr(err)
		}
	}

}

func decryptWorker(id int, data []byte, regex *regexp.Regexp, verbose bool, cKeys <-chan string, cOut chan<- Result) {
	if verbose {
		showInfo(fmt.Sprintf("Worker %d started job", id))
	}
	for key := range cKeys {
		out := decryptUnbased(data, key)
		res := Result{Found: false}
		if isDataString(out) {
			if regex != nil {
				if regex.Match(out) {
					res.Found = true
					res.Key = key
					res.Data = out
				}
			} else {
				res.Found = true
				res.Key = key
				res.Data = out
			}
		}
		cOut <- res
	}
	if verbose {
		showInfo(fmt.Sprintf("Worker %d finished jobs", id))
	}
}

func decrypt(data []byte, key string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0)
	keyLen := len(key)
	for i, char := range raw {
		result = append(result, char^key[i%keyLen])
	}
	return result, nil
}

func decryptUnbased(data []byte, key string) []byte {
	result := make([]byte, 0)
	keyLen := len(key)
	for i, char := range data {
		result = append(result, char^key[i%keyLen])
	}
	return result
}

func encrypt(data []byte, key string) string {
	result := make([]byte, 0)
	keyLen := len(key)
	for i, char := range data {
		result = append(result, char^key[i%keyLen])
	}
	out := base64.StdEncoding.EncodeToString(result)
	return out
}

func readFile(fp string) ([]byte, error) {
	if fi, err := os.Stat(fp); os.IsNotExist(err) {
		return []byte{}, fmt.Errorf("no file - %s", fp)
	} else {
		outBytes := make([]byte, fi.Size())
		f, err := os.Open(fp)
		if err != nil {
			return []byte{}, err
		}
		defer f.Close()
		if _, err := f.Read(outBytes); err != nil {
			return []byte{}, err
		}
		return outBytes, nil
	}
}

func isDataString(data []byte) bool {
	for _, c := range data {
		code := int(rune(c))
		if code > 126 {
			return false
		}
	}
	return true
}

func countLinesInFile(fileName string) (int64, error) {
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return 0, fmt.Errorf("can't find file - %s\n", fileName)
	}
	file, err := os.Open(fileName)

	if err != nil {
		return 0, err
	}

	buf := make([]byte, 1024)
	var lines int64
	for {
		readBytes, err := file.Read(buf)

		if err != nil {
			if readBytes == 0 && err == io.EOF {
				err = nil
			}
			return lines, err
		}

		lines += int64(bytes.Count(buf[:readBytes], []byte{'\n'}))
	}

	return lines, nil
}

func crackWordlistThreaded(data []byte, wlPath string, threads int, regex *regexp.Regexp, updateEverySeconds int) error {

	showInfo(fmt.Sprintf("using regex - %s", regex))
	showInfo(fmt.Sprintf("counting wordlist (%s) lines...", wlPath))
	keyLines, err := countLinesInFile(wlPath)
	if err != nil {
		return err
	}
	showInfo(fmt.Sprintf("total lines - %d", keyLines))
	showInfo(fmt.Sprintf("creating %d crack workers...", threads))
	f, err := os.Open(wlPath)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return err
	}
	var wordCount int64
	var key string
	cKeys := make(chan string, threads)
	cResults := make(chan Result, threads)
	for workerID := 1; workerID < threads+1; workerID++ {
		go decryptWorker(workerID, raw, regex, false, cKeys, cResults)
	}
	go func(count *int64, key *string) {
		for {
			time.Sleep(time.Second * time.Duration(updateEverySeconds))
			log.Printf("Checked: %d [%.2f%% / 100%%]: %s", wordCount, float64(*count)/float64(keyLines)*100, *key)
		}
	}(&wordCount, &key)
	go func(count *int64) {
		for scanner.Scan() {
			key = scanner.Text()
			// handle empty key
			if len(key) == 0 {
				cResults <- Result{Found: false, Key: "", Data: []byte("")}
				*count++
				continue
			}
			cKeys <- key

			*count++
		}
		close(cKeys)
		showInfo("wordlist feeding finished")
	}(&wordCount)
	var countResults int64 = 0
	for result := range cResults {
		countResults++
		if !result.Found {
			if countResults == keyLines {
				log.Printf("Finish count: %d of %d\n", countResults, keyLines)
				break
			}
			continue
		} else {
			log.Printf("KEY: %s <----------------------\n", result.Key)
			fmt.Printf("%s\n", result.Data)
			log.Println("--------------------------")
		}
		if countResults == keyLines {
			log.Printf("Finish count: %d of %d\n", countResults, keyLines)
			break
		}
	}
	close(cResults)
	return nil
}

func showErr(err error) {
	log.Printf("ERROR: %s\n", err)
	os.Exit(0)
}

func showInfo(s string) {
	log.Printf("INFO: %s\n", s)
}
