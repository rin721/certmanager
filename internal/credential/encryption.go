package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type Cipher struct {
	aead cipher.AEAD
}

func NewCipher(masterKey []byte) (*Cipher, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("APP_ENCRYPTION_KEY 至少需要 32 字节")
	}
	key := sha256.Sum256(append([]byte("certmate/dns-credentials/v1:"), masterKey...))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

func (c *Cipher) Encrypt(values map[string]string) ([]byte, error) {
	plaintext, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, []byte("dns_credentials")), nil
}

func (c *Cipher) Decrypt(value []byte) (map[string]string, error) {
	if len(value) < c.aead.NonceSize() {
		return nil, errors.New("加密凭据格式无效")
	}
	nonce, ciphertext := value[:c.aead.NonceSize()], value[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, []byte("dns_credentials"))
	if err != nil {
		return nil, fmt.Errorf("解密 DNS 凭据失败: %w", err)
	}
	var values map[string]string
	if err := json.Unmarshal(plaintext, &values); err != nil {
		return nil, err
	}
	return values, nil
}
