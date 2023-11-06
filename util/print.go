package util

import "fmt"

func PrintBytesAsHex(info string, data []byte) {
	str := "\n"
	for i, b := range data {
		if i > 0 && i%4 == 0 {
			str += " "
		}
		if i > 0 && i%8 == 0 {
			str += "\n"
		}
		str += fmt.Sprintf("%02x ", b)
	}
	str += "\n"
	Log.Info(info + str)
}
