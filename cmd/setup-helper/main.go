// setup-helper 仅在 Docker 部署初始化阶段生成 bcrypt 哈希和随机 Secret。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const (
	passwordBcryptCost = 12
	randomSecretBytes  = 32
	maxPasswordBytes   = 72
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "初始化工具错误:", err)
		os.Exit(1)
	}
}

func run(arguments []string, input io.Reader, output io.Writer) error {
	if len(arguments) != 1 {
		return errors.New("必须指定 hash-password 或 random-secret")
	}
	switch arguments[0] {
	case "hash-password":
		password, err := readPassword(input)
		if err != nil {
			return err
		}
		hash, err := bcrypt.GenerateFromPassword(password, passwordBcryptCost)
		if err != nil {
			return fmt.Errorf("生成 bcrypt 哈希失败: %w", err)
		}
		_, err = fmt.Fprintln(output, string(hash))
		return err
	case "random-secret":
		secret := make([]byte, randomSecretBytes)
		if _, err := rand.Read(secret); err != nil {
			return fmt.Errorf("生成随机 Secret 失败: %w", err)
		}
		_, err := fmt.Fprintln(output, hex.EncodeToString(secret))
		return err
	default:
		return fmt.Errorf("未知操作 %q", arguments[0])
	}
}

func readPassword(input io.Reader) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(input, maxPasswordBytes+3))
	if err != nil {
		return nil, fmt.Errorf("读取管理员密码失败: %w", err)
	}
	value = []byte(strings.TrimSuffix(strings.TrimSuffix(string(value), "\n"), "\r"))
	if len(value) == 0 {
		return nil, errors.New("管理员密码不能为空")
	}
	if len(value) > maxPasswordBytes {
		return nil, fmt.Errorf("管理员密码不能超过 %d 字节", maxPasswordBytes)
	}
	return value, nil
}
