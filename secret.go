package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/fatih/color"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
)

var (
	version = "dev"
	helpMsg = `Secret - Encrypt anything with a password
Usage:
   secret [-e/--encrypt | -d/--decrypt] <source> [<destination>]
   secret [-h/--help | -v/--version]
Options:
   -e, --encrypt   Encrypt the source file and save to destination. If no
                   destination is specified, secret makes a new file with a
                   .secret extension. This option reads stdin for a password.
   -d, --decrypt   Decrypt the source file and save to destination. If no
                   destination is specified, secret makes a new file without
                   the .secret extension. This option reads for a password.
   -h, --help      Display this help message
   -v, --version   Show secret's version
Examples:
   secret -e foo              # creates an encrypted foo.secret file
   secret -d foo.secret bar   # decrypts foo.secret in bar (now same as foo)
Note:
   Secret will never overwrite files and will exit with code 1 in this scenario`
	cryptoStrength = 16384
)

func main() {
	var (
		data      []byte
		writeTo   io.Writer = os.Stdin
		toEncrypt bool
		err       error
		f         *os.File
	)
	if len(os.Args) == 1 {
		handleErrStr("Too few arguments")
		fmt.Println(helpMsg)
		return
	}
	if hasOption, _ := argsHaveOption("help", "h"); hasOption {
		fmt.Println(helpMsg)
		return
	}
	if hasOption, _ := argsHaveOption("version", "v"); hasOption {
		fmt.Println("Secret " + version)
		return
	}
	if os.Args[1] == "-e" || os.Args[1] == "--encrypt" || os.Args[1] == "--make" {
		toEncrypt = true
		f, err = os.Open(os.Args[2])
		if err != nil {
			handleErr(err)
			return
		}
		data, err = ioutil.ReadAll(f)
	}
	if os.Args[1] == "-d" || os.Args[1] == "--decrypt" || os.Args[1] == "--spill" {
		toEncrypt = false
		f, err = os.Open(os.Args[2])
		if err != nil {
			handleErr(err)
			return
		}
		data, err = ioutil.ReadAll(f)
	}

	if len(os.Args) > 3 { // check if user wants to write to some file: `secret --encrypt data writeTo`
		writeTo, err = os.Create(os.Args[3])
		if err != nil {
			handleErr(err)
			return
		}
	} else { // automatically determine where to write to
		if toEncrypt {
			if exists(os.Args[2] + ".secret") {
				handleErrStr("Will not overwrite " + os.Args[2] + ".secret")
				os.Exit(1)
				return
			}
			writeTo, err = os.Create(os.Args[2] + ".secret")
		} else {
			s := strings.TrimSuffix(os.Args[2], ".secret")
			if exists(s) {
				handleErrStr("Will not overwrite " + s)
				os.Exit(1)
				return
			}
			writeTo, err = os.Create(s)
		}
	}
	fmt.Print("Password for your data: ")
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()

	if err != nil {
		handleErr(err)
		return
	}
	result, err := secret(data, string(password), toEncrypt)
	if err != nil {
		handleErr(err)
		return
	}
	writeTo.Write(result)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !(os.IsNotExist(err))
}

func secret(data []byte, password string, toEncrypt bool) ([]byte, error) {
	if toEncrypt {
		return encrypt([]byte(password), data)
	} else {
		return decrypt([]byte(password), data)
	}
}

// Thanks to https://bruinsslot.jp/post/golang-crypto/ for crypto logic
func encrypt(key, data []byte) ([]byte, error) {
	key, salt, err := deriveKey(key, nil)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}

func decrypt(key, data []byte) ([]byte, error) {
	salt, data := data[len(data)-32:], data[:len(data)-32]
	key, _, err := deriveKey(key, salt)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	key, err := scrypt.Key(password, salt, cryptoStrength, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

func argsHaveOption(long string, short string) (hasOption bool, foundAt int) {
	for i, arg := range os.Args {
		if arg == "--"+long || arg == "-"+short {
			return true, i
		}
	}
	return false, 0
}

func handleErr(err error) {
	handleErrStr(err.Error())
}

func handleErrStr(str string) {
	_, _ = fmt.Fprintln(os.Stderr, color.RedString("error: ")+str)
}
