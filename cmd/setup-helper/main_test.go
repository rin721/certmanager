package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"hash-password"}, strings.NewReader("correct horse battery staple\n"), &output); err != nil {
		t.Fatal(err)
	}
	hash := strings.TrimSpace(output.String())
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("correct horse battery staple")); err != nil {
		t.Fatalf("生成的 bcrypt 哈希无法验证原密码: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || cost != passwordBcryptCost {
		t.Fatalf("bcrypt cost = %d, want %d", cost, passwordBcryptCost)
	}
	if strings.Contains(hash, "correct horse") {
		t.Fatal("输出不得包含明文密码")
	}
}

func TestRandomSecret(t *testing.T) {
	var first bytes.Buffer
	var second bytes.Buffer
	if err := run([]string{"random-secret"}, strings.NewReader(""), &first); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"random-secret"}, strings.NewReader(""), &second); err != nil {
		t.Fatal(err)
	}
	firstValue := strings.TrimSpace(first.String())
	secondValue := strings.TrimSpace(second.String())
	decoded, err := hex.DecodeString(firstValue)
	if err != nil || len(decoded) != randomSecretBytes {
		t.Fatalf("随机 Secret 格式无效: %q", firstValue)
	}
	if firstValue == secondValue {
		t.Fatal("两次生成的随机 Secret 不应相同")
	}
}

func TestRejectsInvalidPassword(t *testing.T) {
	for name, password := range map[string]string{
		"empty":    "\n",
		"too-long": strings.Repeat("a", maxPasswordBytes+1) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := run([]string{"hash-password"}, strings.NewReader(password), &bytes.Buffer{}); err == nil {
				t.Fatal("无效密码应被拒绝")
			}
		})
	}
}
