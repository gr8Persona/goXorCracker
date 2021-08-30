# goXorCracker
XOR threaded encryption / decryption / crack utility for CTFs (do not use such encryption in production!) 

OPTIONS:  
```
  -crack
        crack the password by using wordlist (use -w key for file path)
  -decrypt
        decrypt file
  -encrypt
        encrypt file
  -in string
        input file path
  -key string
        password
  -regex string
        GOLANG regex for known data search in decoded ASCII data (default "(?i)\\b(cipher|plaintext|information|alice)")
  -t int
        threads for cracking (default 4)
  -w string
        wordlist file path```