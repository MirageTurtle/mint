package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"

	"github.com/bifurcation/mint"
)

var url string
var dontValidate bool
var useTokenAuth bool
var token string
var privateKeyFile string

func main() {
	c := mint.Config{}

	url := flag.String("url", "https://localhost:4430", "URL to send request")
	flag.BoolVar(&dontValidate, "dontvalidate", false, "don't validate certs")
	flag.BoolVar(&useTokenAuth, "tokenauth", false, "use token auth")
	flag.StringVar(&token, "token", "", "token to use for token auth")
	flag.StringVar(&privateKeyFile, "key", "", "private key file for token auth")
	flag.Parse()
	if dontValidate {
		c.InsecureSkipVerify = true
	}
	if useTokenAuth {
		if token == "" {
			fmt.Println("Must provide a token with -token when using -tokenauth")
			return
		}
		c.UseTokenAuth = true
		c.Token = token
	}
	if privateKeyFile != "" {
		keyPEM, err := os.ReadFile(privateKeyFile)
		if err != nil {
			fmt.Println("Error reading private key file:", err)
			return
		}

		var priv interface{}
		var signer crypto.Signer

		rest := keyPEM
		for len(rest) > 0 {
			block, remaining := pem.Decode(rest)
			if block == nil {
				fmt.Println("No PEM block found in private key file")
				break
			}
			rest = remaining

			switch block.Type {
			case "PRIVATE KEY":
				// PKCS#8 format (private key could be RSA, ECDSA, or Ed25519)
				priv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					fmt.Println("Error parsing PKCS#8 private key:", err)
					return
				}
				var ok bool
				signer, ok = priv.(crypto.Signer)
				if !ok {
					fmt.Println("Parsed key is not a crypto.Signer")
					return
				}
			case "EC PRIVATE KEY":
				// EC private key in SEC 1 format (typically P-256, P-384, or P-521)
				priv, err = x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					fmt.Println("Error parsing EC private key:", err)
					return
				}
				signer = priv.(*ecdsa.PrivateKey)
			case "EC PARAMETERS":
				// Ignore EC PARAMETERS blocks
				fmt.Println("Ignoring EC PARAMETERS block")
				continue
			case "RSA PRIVATE KEY":
				// RSA private key in PKCS#1 format
				// priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				err = fmt.Errorf("RSA PRIVATE KEY format not supported, use PKCS#8 instead")
				if err != nil {
					fmt.Println("Error parsing RSA private key:", err)
					return
				}
			default:
				// err = fmt.Errorf("unsupported private key type: %s", block.Type)
				// fmt.Println(err)
				// return
				fmt.Println("Unsupported private key type:", block.Type)
				continue
			}
			if signer != nil {
				break
			}
		}
		if signer == nil {
			fmt.Println("No valid private key found in file")
			return
		}

		c.ClientPrivateKey = signer
	}

	mintdial := func(network, addr string) (net.Conn, error) {
		return mint.Dial(network, addr, &c)
	}

	tr := &http.Transport{
		DialTLS:            mintdial,
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}

	response, err := client.Get(*url)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	defer response.Body.Close()

	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(contents))
}
