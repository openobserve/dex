package server

import (
	"time"

	"golang.org/x/exp/rand"
)

var stdNums = []byte("0123456789")

// copied from https://github.com/openobserve/casdoor/blob/master/object/verification.go#L357-L367
func getRandomCode(length int) string {
	var result []byte
	r := rand.New(rand.NewSource(uint64(time.Now().UnixNano())))
	for i := 0; i < length; i++ {
		result = append(result, stdNums[r.Intn(len(stdNums))])
	}
	return string(result)
}
