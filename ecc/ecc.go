package ecc

/*
#include "ecc.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

type EccCurve C.int

const (
	Secp_128_r1 EccCurve = C.secp128r1
	Secp_192_r1 EccCurve = C.secp192r1
	Secp_256_r1 EccCurve = C.secp256r1
	Secp_384_r1 EccCurve = C.secp384r1

	EccBytes = int(C.ECC_BYTES)
)

func GetEccCurve() EccCurve {
	return C.ECC_CURVE
}

func (c EccCurve) String() string {
	switch c {
	case Secp_128_r1:
		return "secp128r1"
	case Secp_192_r1:
		return "secp192r1"
	case Secp_256_r1:
		return "secp256r1"
	case Secp_384_r1:
		return "secp384r1"
	default:
		return fmt.Sprintf("unsupported EccCurve: %d", int(c))
	}
}

func MakeKey() ([EccBytes + 1]uint8, [EccBytes]uint8, error) {
	pubKey := [EccBytes + 1]uint8{}
	priKey := [EccBytes]uint8{}
	var cPubKeyPtr = (*C.uint8_t)(unsafe.Pointer(&pubKey))
	var cPriKeyPtr = (*C.uint8_t)(unsafe.Pointer(&priKey))
	ret, err := C.ecc_make_key(cPubKeyPtr, cPriKeyPtr)
	if err != nil {
		return pubKey, priKey, err
	}
	if int(ret) != 1 {
		return pubKey, priKey, fmt.Errorf("ecc_make_key failure: expect=1, found=%d", int(ret))
	}
	return pubKey, priKey, nil
}

func Sign(priKey [EccBytes]uint8, hash [EccBytes]uint8) ([EccBytes * 2]uint8, error) {
	sign := [EccBytes * 2]uint8{}
	var cPriKeyPtr = (*C.uint8_t)(unsafe.Pointer(&priKey))
	var cHashPtr = (*C.uint8_t)(unsafe.Pointer(&hash))
	var cSignPtr = (*C.uint8_t)(unsafe.Pointer(&sign))
	ret, err := C.ecdsa_sign(cPriKeyPtr, cHashPtr, cSignPtr)
	if err != nil {
		return sign, err
	}
	if int(ret) != 1 {
		return sign, fmt.Errorf("ecdsa_sign failure: expect=1, found=%d", int(ret))
	}
	return sign, err
}

func Verify(pubKey [EccBytes + 1]uint8, hash [EccBytes]uint8, sign [EccBytes * 2]uint8) (bool, error) {
	var cPubKeyPtr = (*C.uint8_t)(unsafe.Pointer(&pubKey))
	var cHashPtr = (*C.uint8_t)(unsafe.Pointer(&hash))
	var cSignPtr = (*C.uint8_t)(unsafe.Pointer(&sign))
	ret, err := C.ecdsa_verify(cPubKeyPtr, cHashPtr, cSignPtr)
	if err != nil {
		return false, err
	}
	if int(ret) == 0 {
		return false, nil
	}
	return true, nil
}
