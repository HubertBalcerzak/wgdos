package main

import (
	"github.com/natefinch/npipe"
	"os"
	"log"
	"io"
	"strings"
	"crypto/rand"
	"fmt"
	"encoding/hex"
	"encoding/base64"
	"io/ioutil"
	"golang.org/x/crypto/curve25519"
	"net"
)

func loadConfig(configName string, conn net.Conn) error {
	conf, err := ioutil.ReadFile(configName)
	if err != nil {
		return err
	}
	conn.Write([]byte("set=1\n"))
	conn.Write(conf)
	conn.Write([]byte("\n"))
	_, err = io.Copy(os.Stdout, conn)
	return err
}

var defaultConfig = []string{
	"private_key=%s",
	"listen_port=51820",
	"replace_peers=true",
	"public_key=%s",
	"preshared_key=0000000000000000000000000000000000000000000000000000000000000000",
	"replace_allowed_ips=true",
	"allowed_ip=%s",
	"endpoint=%s",
	"persistent_keepalive_interval=5",
	"",
}

func generateKey(rand io.Reader) (publicKey, privateKey *[32]byte, err error) {

	publicKey = new([32]byte)
	privateKey = new([32]byte)
	_, err = io.ReadFull(rand, privateKey[:])
	if err != nil {
		publicKey = nil
		privateKey = nil
		return
	}
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64
	curve25519.ScalarBaseMult(publicKey, privateKey)

	return
}

func createConfig(configName, peerPublic, allowedIp, endPoint string) error {
	public, private, err := generateKey(rand.Reader)
	if err != nil {
		return err
	}
	peerPublicDecoded, err := base64.StdEncoding.DecodeString(peerPublic)
	config := fmt.Sprintf(strings.Join(defaultConfig, "\n"),
		hex.EncodeToString(private[:]),
		hex.EncodeToString(peerPublicDecoded),
		allowedIp,
		endPoint)
	err = ioutil.WriteFile(configName+".conf", []byte(config), 0600)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(configName+".pk", []byte(base64.StdEncoding.EncodeToString(public[:])), 0600)
}

func main() {
	switch os.Args[1] {
	case "get":
		conn, err := npipe.Dial(fmt.Sprintf(`\\.\pipe\wireguard-ipc-%s`, os.Args[2]))
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		conn.Write([]byte("get=1\n\n"))
		_, err = io.Copy(os.Stdout, conn)
	case "genconfig":
		if len(os.Args) != 6 {
			fmt.Println("usage: wgdos genconfig configName peerPublic allowedIp endPoint")
		}
		err := createConfig(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
		if err != nil {
			log.Fatal(err)
		}
	case "loadconf":
		if len(os.Args) != 4 {
			fmt.Println("usage: wgdos loadconf interface configname")
		}
		conn, err := npipe.Dial(fmt.Sprintf(`\\.\pipe\wireguard-ipc-%s`, os.Args[2]))
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()
		loadConfig(os.Args[3], conn)
	default:

	}

}
