// Package files 负责在受控证书根目录内安全发布证书文件。
package files

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var allowedFiles = map[string]os.FileMode{
	"cert.pem":      0o644,
	"chain.pem":     0o644,
	"fullchain.pem": 0o644,
	"privkey.pem":   0o600,
	"metadata.json": 0o644,
}

var safeDirectoryPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func ValidateSafeDirectory(name string) error {
	if !safeDirectoryPattern.MatchString(name) || strings.Contains(name, "..") {
		return errors.New("输出目录名只能包含小写字母、数字和连字符，长度为 1 到 63")
	}
	return nil
}

type Publisher struct {
	root      string
	backupDir string
	now       func() time.Time
}

type Payload struct {
	CertPEM       []byte
	ChainPEM      []byte
	FullchainPEM  []byte
	PrivateKeyPEM []byte
	MetadataJSON  []byte
	CreateMarker  bool
}

// BackupResult 描述删除前备份是否实际处理了已发布目录。
type BackupResult struct {
	DirectoryExisted bool
	BackupCreated    bool
}

func NewPublisher(root, backupDir string) *Publisher {
	return &Publisher{root: filepath.Clean(root), backupDir: filepath.Clean(backupDir), now: time.Now}
}

func (p *Publisher) Publish(safeName string, payload Payload) (string, error) {
	if err := ValidateSafeDirectory(safeName); err != nil {
		return "", err
	}
	if err := ensureRoot(p.root); err != nil {
		return "", err
	}
	if err := os.MkdirAll(p.backupDir, 0o750); err != nil {
		return "", fmt.Errorf("创建备份目录: %w", err)
	}
	stage, err := os.MkdirTemp(p.root, "."+safeName+".stage-")
	if err != nil {
		return "", fmt.Errorf("创建发布暂存目录: %w", err)
	}
	if err := os.Chmod(stage, 0o750); err != nil {
		_ = os.Remove(stage)
		return "", fmt.Errorf("设置暂存目录权限: %w", err)
	}
	cleanupStage := true
	defer func() {
		if cleanupStage {
			_ = removeManagedDirectory(p.root, stage)
		}
	}()

	values := map[string][]byte{
		"cert.pem": payload.CertPEM, "chain.pem": payload.ChainPEM,
		"fullchain.pem": payload.FullchainPEM, "privkey.pem": payload.PrivateKeyPEM,
		"metadata.json": payload.MetadataJSON,
	}
	for name, mode := range allowedFiles {
		if len(values[name]) == 0 {
			return "", fmt.Errorf("待发布文件 %s 为空", name)
		}
		if err := os.WriteFile(filepath.Join(stage, name), values[name], mode); err != nil {
			return "", fmt.Errorf("写入 %s: %w", name, err)
		}
		if err := os.Chmod(filepath.Join(stage, name), mode); err != nil {
			return "", fmt.Errorf("设置 %s 权限: %w", name, err)
		}
	}
	if payload.CreateMarker {
		if err := os.WriteFile(filepath.Join(stage, ".renewed"), []byte(p.now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
			return "", fmt.Errorf("创建更新标记: %w", err)
		}
	}

	target := filepath.Join(p.root, safeName)
	if err := validateTarget(p.root, target); err != nil {
		return "", err
	}
	if info, statErr := os.Lstat(target); statErr == nil {
		if !info.IsDir() {
			return "", errors.New("证书输出目标不是目录")
		}
		backupTarget := filepath.Join(p.backupDir, safeName+"-"+p.now().UTC().Format("20060102T150405.000000000Z"))
		if err := copyManagedDirectory(target, backupTarget); err != nil {
			return "", fmt.Errorf("备份现有证书: %w", err)
		}
		swapBackup, err := os.MkdirTemp(p.root, "."+safeName+".previous-")
		if err != nil {
			return "", err
		}
		if err := os.Remove(swapBackup); err != nil {
			return "", err
		}
		if err := os.Rename(target, swapBackup); err != nil {
			return "", fmt.Errorf("切换旧证书目录: %w", err)
		}
		if err := os.Rename(stage, target); err != nil {
			_ = os.Rename(swapBackup, target)
			return "", fmt.Errorf("发布新证书目录: %w", err)
		}
		cleanupStage = false
		_ = removeManagedDirectory(p.root, swapBackup)
	} else if errors.Is(statErr, os.ErrNotExist) {
		if err := os.Rename(stage, target); err != nil {
			return "", fmt.Errorf("发布证书目录: %w", err)
		}
		cleanupStage = false
	} else {
		return "", fmt.Errorf("检查证书输出目标: %w", statErr)
	}
	return target, nil
}

func (p *Publisher) Read(safeName, fileName string) ([]byte, os.FileMode, error) {
	if err := ValidateSafeDirectory(safeName); err != nil {
		return nil, 0, err
	}
	mode, allowed := allowedFiles[fileName]
	if !allowed {
		return nil, 0, errors.New("不支持的证书文件类型")
	}
	target := filepath.Join(p.root, safeName)
	if err := validateTarget(p.root, target); err != nil {
		return nil, 0, err
	}
	filename := filepath.Join(target, fileName)
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("证书文件不是普通文件")
	}
	value, err := os.ReadFile(filename)
	return value, mode, err
}

func (p *Publisher) Backup(safeName string) (BackupResult, error) {
	if err := ValidateSafeDirectory(safeName); err != nil {
		return BackupResult{}, err
	}
	if err := ensureRoot(p.root); err != nil {
		return BackupResult{}, err
	}
	target := filepath.Join(p.root, safeName)
	if err := validateTarget(p.root, target); err != nil {
		return BackupResult{}, err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return BackupResult{}, nil
	}
	if err != nil {
		return BackupResult{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return BackupResult{}, errors.New("证书输出目标不是安全目录")
	}
	if err := os.MkdirAll(p.backupDir, 0o750); err != nil {
		return BackupResult{DirectoryExisted: true}, err
	}
	backupTarget := filepath.Join(p.backupDir, safeName+"-deleted-"+p.now().UTC().Format("20060102T150405.000000000Z"))
	if err := copyManagedDirectory(target, backupTarget); err != nil {
		return BackupResult{DirectoryExisted: true}, err
	}
	return BackupResult{DirectoryExisted: true, BackupCreated: true}, nil
}

// Available 返回受管目录中实际存在且安全的证书文件。
func (p *Publisher) Available(safeName string) (map[string]bool, error) {
	if err := ValidateSafeDirectory(safeName); err != nil {
		return nil, err
	}
	if err := ensureRoot(p.root); err != nil {
		return nil, err
	}
	target := filepath.Join(p.root, safeName)
	if err := validateTarget(p.root, target); err != nil {
		return nil, err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("证书输出目标不是安全目录")
	}

	available := make(map[string]bool, len(allowedFiles))
	for name := range allowedFiles {
		fileInfo, statErr := os.Lstat(filepath.Join(target, name))
		if errors.Is(statErr, os.ErrNotExist) {
			continue
		}
		if statErr != nil {
			return nil, statErr
		}
		if !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("证书文件 %s 不是普通文件", name)
		}
		available[name] = true
	}
	return available, nil
}

func (p *Publisher) Remove(safeName string) error {
	if err := ValidateSafeDirectory(safeName); err != nil {
		return err
	}
	target := filepath.Join(p.root, safeName)
	if err := validateTarget(p.root, target); err != nil {
		return err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("证书输出目标不是安全目录")
	}
	return removeManagedDirectory(p.root, target)
}

func ensureRoot(root string) error {
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("检查证书根目录: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("证书根目录必须是非符号链接目录")
	}
	return nil
}

func validateTarget(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("证书路径逃逸")
	}
	if info, statErr := os.Lstat(target); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return errors.New("证书目录不能是符号链接")
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	return nil
}

func copyManagedDirectory(source, target string) error {
	if err := os.Mkdir(target, 0o750); err != nil {
		return err
	}
	completed := false
	defer func() {
		if !completed {
			_ = removeManagedDirectory(filepath.Dir(target), target)
		}
	}()
	for name, mode := range allowedFiles {
		sourceFile := filepath.Join(source, name)
		info, err := os.Lstat(sourceFile)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("备份源文件 %s 不是普通文件", name)
		}
		input, err := os.Open(sourceFile)
		if err != nil {
			return err
		}
		openedInfo, statErr := input.Stat()
		if statErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
			input.Close()
			return fmt.Errorf("备份源文件 %s 在读取前发生变化", name)
		}
		output, err := os.OpenFile(filepath.Join(target, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		input.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	markerPath := filepath.Join(source, ".renewed")
	if markerInfo, err := os.Lstat(markerPath); err == nil {
		if !markerInfo.Mode().IsRegular() || markerInfo.Mode()&os.ModeSymlink != 0 {
			return errors.New("更新标记不是普通文件")
		}
		marker, readErr := os.ReadFile(markerPath)
		if readErr != nil {
			return readErr
		}
		if err := os.WriteFile(filepath.Join(target, ".renewed"), marker, 0o644); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	completed = true
	return nil
}

func removeManagedDirectory(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return errors.New("拒绝清理非托管目录")
	}
	return os.RemoveAll(target)
}
