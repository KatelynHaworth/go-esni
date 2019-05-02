package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"

	esni "github.com/LiamHaworth/go-esni"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s [domain]", os.Args[0])
		fmt.Println()
		fmt.Println("Parameters:")
		fmt.Println("\t[domain] - Specifies the domain name to fetch and parse the ESNI records of")
		fmt.Println()
		return
	}

	records, err := net.LookupTXT(fmt.Sprintf("_esni.%s", os.Args[1]))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Target Domain: %s\n", os.Args[1])
	fmt.Println()

	for i := range records {
		fmt.Printf("----------- ESNI Record %d\n", i)
		data, err := base64.StdEncoding.DecodeString(records[i])
		if err != nil {
			fmt.Printf("ERROR: Decode record data: %s\n", err)
			continue
		}

		fmt.Print(hex.Dump(data))
		fmt.Println()

		key := new(esni.Keys)
		if err := key.UnmarshalBinary(data); err != nil {
			fmt.Printf("ERROR: Unmarshal record data: %s\n", err)
			continue
		}

		fmt.Println(key)
		fmt.Println("-----------")
	}
}
