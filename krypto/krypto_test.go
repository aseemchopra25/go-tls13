// t.Errorf("Error: %q", x)
package krypto

import (
	"encoding/hex"
	"testing"
)

func TestPublicKey(t *testing.T) {
	testPubKey := "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
	testPrivateKey, _ := hex.DecodeString("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")

	pub := hex.EncodeToString(createPublicKey(testPrivateKey))
	if pub != testPubKey {
		t.Errorf("Key Pair Generation Failure")
	}

}
