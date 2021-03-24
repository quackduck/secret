package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	pb "github.com/schollz/progressbar/v3"
	"github.com/secure-io/sio-go"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

var (
	version = "dev"
	helpMsg = `Secret - Encrypt anything with a password
Usage:
   secret {-e/--encrypt | -d/--decrypt} <source> [<destination>]
   secret [-h/--help | -v/--version]
Options:
   -e, --encrypt   Encrypt the source file and save to destination. If no
                   destination is specified, secret makes a new file with a
                   .secret extension. This option reads for a password.
   -d, --decrypt   Decrypt the source file and save to destination. If no
                   destination is specified, secret makes a new file without
                   the .secret extension. This option reads for a password.
   -h, --help      Display this help message
   -v, --version   Show secret's version
Examples:
   secret -e foo                 # creates an encrypted foo.secret file
   secret -d foo.secret bar      # decrypts foo.secret in bar (now same as foo)
   echo "pass" | secret -e foo   # use "pass" as password and encrypt foo
Note:
   Secret will never overwrite files and will exit with code 1 in this scenario`
	cryptoStrength = 15 // scrypt's N = 2^15 = 32,768 // TODO: Make this 16 in Secret 2.0
)

// TODO: Consider changing encryption algo to ChaCha20 in Secret 2.0

func main() { //nolint:gocyclo
	var (
		src       io.Reader
		dst       io.Writer
		toEncrypt bool
		size      int64 = -1
	)
	if hasOption, _ := argsHaveOption("help", "h"); hasOption {
		fmt.Println(helpMsg)
		return
	}
	if hasOption, _ := argsHaveOption("version", "v"); hasOption {
		fmt.Println("Secret " + version)
		return
	}
	if len(os.Args) < 3 { // at least two args needed
		handleErrStr("Too few arguments")
		fmt.Println(helpMsg)
		return
	}
	if os.Args[1] == "-e" || os.Args[1] == "--encrypt" || os.Args[1] == "--make" {
		toEncrypt = true
		f, err := os.Open(os.Args[2])
		if err != nil {
			handleErr(err)
			return
		}
		src = f
		stat, err := f.Stat()
		if err != nil {
			handleErr(err)
			return
		}
		size = stat.Size()
	}
	if os.Args[1] == "-d" || os.Args[1] == "--decrypt" || os.Args[1] == "--spill" {
		toEncrypt = false
		f, err := os.Open(os.Args[2])
		if err != nil {
			handleErr(err)
			return
		}
		src = f
		stat, err := f.Stat()
		if err != nil {
			handleErr(err)
			return
		}
		size = stat.Size()
	}

	var err error
	if len(os.Args) > 3 { // check if user wants to write to some file: `secret --encrypt data dst`
		dst, err = os.Create(os.Args[3])
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
			dst, err = os.Create(os.Args[2] + ".secret")
			if err != nil {
				handleErr(err)
				return
			}
		} else {
			s := strings.TrimSuffix(os.Args[2], ".secret")
			if exists(s) {
				handleErrStr("Will not overwrite " + s)
				os.Exit(1)
				return
			}
			dst, err = os.Create(s)
			if err != nil {
				handleErr(err)
				return
			}
		}
	}

	var password []byte // default pass

	fi, _ := os.Stdin.Stat() //nolint:errcheck // stat stdin will be fine

	if (fi.Mode() & os.ModeCharDevice) == 0 { // password is being piped
		password, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			handleErr(err)
			return
		}
	} else {
		fmt.Print("Password: ")
		password, err = term.ReadPassword(int(syscall.Stdin)) //nolint:unconvert
		fmt.Print("\033[2K\r")
		if err != nil {
			handleErr(err)
			return
		}
	}
	err = secret(password, src, dst, toEncrypt, size)
	if err != nil {
		handleErr(err)
		return
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !(os.IsNotExist(err))
}

func secret(password []byte, src io.Reader, dst io.Writer, toEncrypt bool, size int64) error {
	if toEncrypt {
		return encrypt(password, src, dst, size)
	}
	return decrypt(password, src, dst, size)
}

// Thanks to https://bruinsslot.jp/post/golang-crypto/ for some of the crypto logic
func encrypt(pass []byte, src io.Reader, dst io.Writer, size int64) error {
	start := time.Now()
	key, salt, err := deriveKey(pass, nil)
	keyDur := time.Since(start).Round(time.Millisecond)
	if err != nil {
		return err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return err
	}
	stream := sio.NewStream(gcm, sio.BufSize)
	pbar := pb.NewOptions64(size,
		pb.OptionEnableColorCodes(true),
		pb.OptionShowBytes(true),
		pb.OptionSetWriter(os.Stderr),
		pb.OptionThrottle(65*time.Millisecond),
		pb.OptionShowCount(),
		pb.OptionClearOnFinish(),
		pb.OptionSetDescription("Encrypting"),
		pb.OptionFullWidth(),
		pb.OptionSetTheme(pb.Theme{
			Saucer:        "█",
			SaucerPadding: " ",
			BarStart:      "",
			BarEnd:        "",
		}))
	nonce := make([]byte, stream.NonceSize())
	rand.Read(nonce) //nolint:errcheck
	// attach salt at the start
	dst.Write(append(salt, nonce...)) //nolint:errcheck

	dst = io.MultiWriter(dst, pbar) // attach progress bar
	// make reader encrypted
	src = stream.EncryptReader(src, nonce, nil)
	_, err = io.Copy(dst, src)
	pbar.Finish() //nolint:errcheck
	fmt.Println("Done in", time.Since(start).Round(time.Millisecond).String()+".", "Key derivation took", keyDur)
	return err
}

func decrypt(pass []byte, src io.Reader, dst io.Writer, size int64) error {
	start := time.Now()
	salt := make([]byte, 32)
	_, err := src.Read(salt) // read in salt from the beginning
	if err != nil {
		return err
	}
	pass, _, err = deriveKey(pass, salt)
	if err != nil {
		return err
	}
	blockCipher, err := aes.NewCipher(pass)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return err
	}
	stream := sio.NewStream(gcm, sio.BufSize)
	nonce := make([]byte, stream.NonceSize())
	_, err = src.Read(nonce) // read in nonce
	if err != nil {
		return err
	}
	pbar := pb.NewOptions64(size,
		pb.OptionEnableColorCodes(true),
		pb.OptionShowBytes(true),
		pb.OptionSetWriter(os.Stderr),
		pb.OptionThrottle(65*time.Millisecond),
		pb.OptionShowCount(),
		pb.OptionClearOnFinish(),
		pb.OptionSetDescription("Decrypting"),
		pb.OptionFullWidth(),
		pb.OptionSetTheme(pb.Theme{
			Saucer:        "█",
			SaucerPadding: " ",
			BarStart:      "█",
			BarEnd:        "",
		}))

	dst = io.MultiWriter(dst, pbar) // attach progress bar

	src = stream.DecryptReader(src, nonce, nil)
	_, err = io.Copy(dst, src)
	pbar.Finish() //nolint:errcheck
	if err == sio.NotAuthentic {
		return errors.New("authentication failed")
	}
	fmt.Println("Done in", time.Since(start).Round(time.Millisecond).String()+".")
	return err
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	key, err := scrypt.Key(password, salt, 1<<cryptoStrength, 8, 1, 32)
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
