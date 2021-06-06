package function

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	rand "math/rand"
	"os"
	"time"
)

func GenkeyAES() []byte {
	rand.Seed(time.Now().UnixNano())
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	key := make([]byte, 32)
	for i := range key {
		key[i] = letterBytes[rand.Intn(len(letterBytes))]
	}

	return key
}

func GenerateRsaKey() error {
	private, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return err
	}
	//x509 private key serialization
	privateStream := x509.MarshalPKCS1PrivateKey(private)
	// Set the private key to the pem structure
	block := pem.Block{
		Type:  "Rsa Private Key",
		Bytes: privateStream,
	}
	//Save the disk
	file, err := os.Create("privateKey.pem")
	if err != nil {
		return err
	}
	//pem encoding
	err = pem.Encode(file, &block)
	if err != nil {
		return err
	}
	//=========public=========
	public := private.PublicKey
	//509 serialization
	publicStream, err := x509.MarshalPKIXPublicKey(&public)
	if err != nil {
		return err
	}
	// public key assignment pem structure
	pubblock := pem.Block{Type: "Rsa Public Key", Bytes: publicStream}
	//Save the disk
	pubfile, err := os.Create("publicKey.pem")
	if err != nil {
		return err
	}
	//pem encoding
	err = pem.Encode(pubfile, &pubblock)
	if err != nil {
		return err
	}
	return nil

}

func SignatureRSA(sourceData []byte) ([]byte, error) {
	msg := []byte("")
	// Read the private key from the file
	file, err := os.Open("privateKey.pem")
	if err != nil {
		return msg, err
	}
	info, err := file.Stat()
	if err != nil {
		return msg, err
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	// Analysis
	block, _ := pem.Decode(buf)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return msg, err
	}
	//Hash encryption
	myHash := sha512.New()
	myHash.Write(sourceData)
	hashRes := myHash.Sum(nil)
	fmt.Printf("Hash : %x\n", hashRes)
	// Sign the hash result
	res, err := rsa.SignPKCS1v15(crand.Reader, privateKey, crypto.SHA512, hashRes)
	if err != nil {
		return msg, err
	}
	defer file.Close()
	return res, nil
}

func VerifyRSA(sourceData, signedDataBase64 []byte) error {
	readfileTostring := string(signedDataBase64)
	signedData, err := base64.StdEncoding.DecodeString(readfileTostring)
	if err != nil {
		fmt.Println("Checksum error:", err)
	}
	file, err := os.Open("publicKey.pem")
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem decryption
	block, _ := pem.Decode(buf)
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	publicKey := publicInterface.(*rsa.PublicKey)
	// metadata hash encryption
	mySha := sha512.New()
	mySha.Write(sourceData)
	res := mySha.Sum(nil)

	//Verify the signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, res, signedData)
	if err != nil {
		return err
	}
	defer file.Close()
	return nil

}

func EncryptAES(key []byte, message string) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(crand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func DecryptAES(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("CiphertextBlockSizeIsTooShort")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}

func ReadLine() string {
	bio := bufio.NewReader(os.Stdin)
	line, _, err := bio.ReadLine()
	if err != nil {
		fmt.Println(err)
	}
	return string(line)
}

func WriteToFile(data, file string) {
	ioutil.WriteFile(file, []byte(data), 0644)
}

func ReadFromFile(file string) ([]byte, error) {
	data, err := ioutil.ReadFile(file)
	return data, err
}
