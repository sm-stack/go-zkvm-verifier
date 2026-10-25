package leanvm_test

import (
	"fmt"
	"github.com/sm-stack/go-zkvm-verifier/leanvm"
	"os"
)

func ExampleVerify() {
	elf, err := os.ReadFile("testdata/fibonacci.elf")
	if err != nil {
		panic(err)
	}
	output, err := os.ReadFile("testdata/fibonacci-1000.output")
	if err != nil {
		panic(err)
	}
	proof, err := os.ReadFile("testdata/fibonacci-1000.proof")
	if err != nil {
		panic(err)
	}
	digest, err := leanvm.Verify(elf, [32]byte(output), proof)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", digest)
	// Output: bc155cddb5ac075cdc823755a722ad9030cb987d1e1f5430f3b7b40fe907d570
}
