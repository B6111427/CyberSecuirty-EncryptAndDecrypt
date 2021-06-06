package main

import (
	call "cyber/function"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

func main() {
	for {
		
		fmt.Printf(" ___________________________________________________\n")
		fmt.Printf("|                                                   |\n")
		fmt.Printf("|       Welcome to Encrypt and Decrypt program      |\n")
		fmt.Printf("|                       (⌐■_■)                      |\n")
		fmt.Printf(" ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ \n")

		fmt.Printf(" ___________________________________________________\n")
		fmt.Printf("%s%33s%19s\n", "|", "Available Comand", "|")
		fmt.Printf("|   1)Encrypt Text + Digital signature 🔒📝         |\n")
		fmt.Printf("|   2)Decrypt Text + Verify Digital signature 🔓📝  |\n")
		fmt.Printf("|   3)Encrypt File 🔒       4)Decrypt File 🔓       |\n")
		fmt.Printf("|   5)GenRSAKey             0)Exit                  |\n")
		fmt.Printf("|                      (⌐■_■)                       |\n")
		fmt.Printf(" ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ ͞ \n")

		fmt.Print("Input menu number: ")
		menu := call.ReadLine()
		switch menu {
		case "1":
			key := call.GenkeyAES()
			fmt.Println("       1)Encrypt Text + Digital signature 🔒📝")
			fmt.Print("       What is the name of the file to encrypt: ")
			filename := call.ReadLine()
			if plaintext, err := call.ReadFromFile(filename); err != nil {
				fmt.Println("File is not found")
			} else {
				fmt.Printf("\n          -Your AES Key: 🔑 %s 🔑\n\n", key)
				fmt.Println("          *** Note please keep your key to be secret ***")
				if encrypted, err := call.EncryptAES(key, string(plaintext)); err != nil {
					log.Println(err)
				} else {
					call.WriteToFile(encrypted, filename)
					fmt.Printf("Ciphertext : %s\n", encrypted)
					signData, err := call.SignatureRSA([]byte(encrypted))
					if err != nil {
						fmt.Println("cryption error:", err)
					}
					call.WriteToFile(base64.StdEncoding.EncodeToString(signData), "SignatureOutput.txt")
					fmt.Printf("Signature Output : %s\n\n\n\n\n\n\n\n", base64.StdEncoding.EncodeToString(signData))
					fmt.Print("Enter To Continue")
					call.ReadLine()
					fmt.Print("\n\n\n\n\n\n\n\n")
				}
			}
		case "2":
			fmt.Println("       2)Decrypt Text + Verify Digital signature 🔓📝")
			fmt.Print("       What is the name of the file to decrypt: ")
			filename := call.ReadLine()
			fmt.Print("       What is your key to decrypt: ")
			key := call.ReadLine()
			if ciphertext, err := call.ReadFromFile(filename); err != nil {
				fmt.Println("File is not found")
			} else {
				fmt.Printf("          -Ciphertext: %s\n", ciphertext)
				if decrypted, err := call.DecryptAES([]byte(key), string(ciphertext)); err != nil {
					log.Println(err)
				} else {
					fmt.Println("          -Decrypted: " + decrypted)

					signedData, err := call.ReadFromFile("SignatureOutput.txt")
					if err != nil {
						fmt.Println("Checksum error:", err)
					}
					err = call.VerifyRSA(ciphertext, signedData)
					if err != nil {
						fmt.Println("       '❗❓Signature Verification Failed")
					}
					fmt.Printf("       ✅ Signature Verification Passed: %s\n", decrypted)
					call.WriteToFile(decrypted, filename)
					fmt.Print("\n\n\n\n\n\n\n\nEnter To Continue")
					call.ReadLine()
					fmt.Print("\n\n\n\n\n\n\n\n")
				}
			}
		case "3":
			key := call.GenkeyAES()
			fmt.Println("       3)Encrypt File 🔒")
			fmt.Print("       What is the name of the file to encrypt: ")
			filename := call.ReadLine()
			if plaintext, err := call.ReadFromFile(filename); err != nil {
				fmt.Println("File is not found")
			} else {
				fmt.Printf("\n          -Your AES Key: 🔑 %s 🔑\n\n", key)
				fmt.Println("          *** Note please keep your key to be secret ***")
				if encrypted, err := call.EncryptAES(key, string(plaintext)); err != nil {
					log.Println(err)
				} else {
					call.WriteToFile(encrypted, filename)
					fmt.Printf("          ✅ Success your file was encrypt")

					fmt.Print("\n\n\n\n\n\n\n\nEnter To Continue")
					call.ReadLine()
					fmt.Print("\n\n\n\n\n\n\n\n")
				}
			}
		case "4":
			fmt.Println("       4)Decrypt File 🔓")
			fmt.Print("       What is the name of the file to decrypt: ")
			filename := call.ReadLine()
			fmt.Print("       What is your key to decrypt: ")
			key := call.ReadLine()
			if ciphertext, err := call.ReadFromFile(filename); err != nil {
				fmt.Println("File is not found")
			} else {
				if decrypted, err := call.DecryptAES([]byte(key), string(ciphertext)); err != nil {
					log.Println(err)
				} else {
					fmt.Printf("          ✅ Success your file was decrypt")
					call.WriteToFile(decrypted, filename)
				}
				fmt.Print("\n\n\n\n\n\n\n\nEnter To Continue")
				call.ReadLine()
				fmt.Print("\n\n\n\n\n\n\n\n")
			}
		case "5":
			call.GenerateRsaKey()
			fmt.Print("\n\n\n\n\n\n\n\n")
		case "0":
			os.Exit(0)
		}
	}

}
