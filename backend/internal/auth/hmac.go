package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// ValidateSignature verifica se a assinatura recebida bate com os dados + chave secreta
func ValidateSignature(uid string, timestamp int64, nonce string, receivedSig string, secret string) bool {
	message := uid + ":" + itoa(timestamp) + ":" + nonce
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(message))

	expectedSig := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(expectedSig), []byte(receivedSig))
}

func itoa(value int64) string {
	if value == 0 {
		return "0"
	}

	negative := value < 0
	if negative {
		value = -value
	}

	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}

	if negative {
		index--
		digits[index] = '-'
	}

	return string(digits[index:])
}
