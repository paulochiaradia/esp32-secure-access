package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// ValidateSignature verifica se a assinatura recebida bate com os dados + chave secreta
func ValidateSignature(uid string, timestamp int64, nonce string, receivedSig string, secret string) bool {
	message := uid + ":" + strconv.FormatInt(timestamp, 10) + ":" + nonce
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))

	expectedSig := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(receivedSig))
}
