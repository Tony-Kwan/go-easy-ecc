package ecc

import (
	"encoding/hex"
	"testing"
)

func TestGetEccCurve(t *testing.T) {
	t.Log(EccBytes)
	t.Log("Curve:", GetEccCurve())
}

func TestMakeKey(t *testing.T) {
	pubKey, priKey, err := MakeKey()
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(pubKey)
	t.Log(priKey)
}

func TestSign(t *testing.T) {
	pubKeyHex := "0298dd2b270a990d6750a3bbbd466e9570f358c4935e8cc6c85157f60398de3549"
	priKeyHex := "6adcaf573be5e8d56a27122a942b1a5b2afc137210afe10646a2e412a19ba026"
	hashHex := "7066479555585967030553493694485122506577956075909457428640587478"
	pubKeySlice, _ := hex.DecodeString(pubKeyHex)
	priKeySlice, _ := hex.DecodeString(priKeyHex)
	hashSlice, _ := hex.DecodeString(hashHex)
	var pubKey [EccBytes + 1]uint8
	var priKey [EccBytes]uint8
	var hash [EccBytes]uint8
	copy(pubKey[:], pubKeySlice[:EccBytes+1])
	copy(priKey[:], priKeySlice[:EccBytes])
	copy(hash[:], hashSlice[:EccBytes])

	sign, err := Sign(priKey, hash)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log("Public Key:", hex.EncodeToString(pubKey[:]))
	t.Log("Private Key:", hex.EncodeToString(priKey[:]))
	t.Log("Hash:", hex.EncodeToString(hash[:]))
	t.Log("Sign:", hex.EncodeToString(sign[:]))
}

func TestVerify(t *testing.T) {
	pubKeyHex := "0298dd2b270a990d6750a3bbbd466e9570f358c4935e8cc6c85157f60398de3549"
	priKeyHex := "6adcaf573be5e8d56a27122a942b1a5b2afc137210afe10646a2e412a19ba026"
	hashHex := "7066479555585967030553493694485122506577956075909457428640587478"
	pubKeySlice, _ := hex.DecodeString(pubKeyHex)
	priKeySlice, _ := hex.DecodeString(priKeyHex)
	hashSlice, _ := hex.DecodeString(hashHex)
	var pubKey [EccBytes + 1]uint8
	var priKey [EccBytes]uint8
	var hash [EccBytes]uint8
	copy(pubKey[:], pubKeySlice[:EccBytes+1])
	copy(priKey[:], priKeySlice[:EccBytes])
	copy(hash[:], hashSlice[:EccBytes])

	signHex := "f22eb5b75192b9094b3c0955553679e7695f779b7cb10fd1e7743cabb1b52307a794b4cb8b3d565a11991b6398185e20dbca90a539742f2f3e0050c4df1176ea"
	signSlice, _ := hex.DecodeString(signHex)
	var sign [EccBytes * 2]uint8
	copy(sign[:], signSlice[:EccBytes*2])

	valid, err := Verify(pubKey, hash, sign)
	if err != nil {
		t.Error(err)
		return
	}

	t.Log("Ecc Bytes:", EccBytes)
	t.Log("Curve:", GetEccCurve())
	t.Log("Public Key:", hex.EncodeToString(pubKey[:]))
	t.Log("Private Key:", hex.EncodeToString(priKey[:]))
	t.Log("Hash:", hex.EncodeToString(hash[:]))
	t.Log("Sign:", hex.EncodeToString(sign[:]))
	t.Log("Valid:", valid)
}
