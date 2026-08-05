package files

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPublisherWritesExpectedFilesAndPermissions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "certs")
	backups := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	publisher := NewPublisher(root, backups)
	payload := Payload{
		CertPEM: []byte("cert"), ChainPEM: []byte("chain"), FullchainPEM: []byte("fullchain"),
		PrivateKeyPEM: []byte("private"), MetadataJSON: []byte("{}\n"), CreateMarker: true,
	}
	target, err := publisher.Publish("example-com", payload)
	if err != nil {
		t.Fatal(err)
	}
	for name, mode := range allowedFiles {
		info, err := os.Stat(filepath.Join(target, name))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != mode {
			t.Errorf("%s mode=%o want=%o", name, info.Mode().Perm(), mode)
		}
	}
	if _, err := os.Stat(filepath.Join(target, ".renewed")); err != nil {
		t.Fatal("缺少 .renewed 标记")
	}
	if _, _, err := publisher.Read("../escape", "cert.pem"); err == nil {
		t.Fatal("必须拒绝路径逃逸")
	}
	if _, _, err := publisher.Read("example-com", "../../secret"); err == nil {
		t.Fatal("必须拒绝任意文件读取")
	}
}

func TestPublisherRejectsSymlinkTarget(t *testing.T) {
	root := filepath.Join(t.TempDir(), "certs")
	outside := t.TempDir()
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "example-com")); err != nil {
		t.Skipf("当前环境不能创建符号链接: %v", err)
	}
	publisher := NewPublisher(root, filepath.Join(t.TempDir(), "backups"))
	_, err := publisher.Publish("example-com", Payload{CertPEM: []byte("x"), ChainPEM: []byte("x"), FullchainPEM: []byte("x"), PrivateKeyPEM: []byte("x"), MetadataJSON: []byte("{}")})
	if err == nil {
		t.Fatal("必须拒绝符号链接证书目录")
	}
}

func TestPublisherRejectsSymlinkDuringBackup(t *testing.T) {
	root := filepath.Join(t.TempDir(), "certs")
	backups := filepath.Join(t.TempDir(), "backups")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	publisher := NewPublisher(root, backups)
	payload := Payload{CertPEM: []byte("cert"), ChainPEM: []byte("chain"), FullchainPEM: []byte("full"), PrivateKeyPEM: []byte("key"), MetadataJSON: []byte("{}")}
	target, err := publisher.Publish("example-com", payload)
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.pem")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(target, "privkey.pem")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "privkey.pem")); err != nil {
		t.Skipf("当前环境不能创建符号链接: %v", err)
	}
	if _, err := publisher.Publish("example-com", payload); err == nil {
		t.Fatal("备份阶段必须拒绝跟随符号链接")
	}
}

func TestPublisherBackupTreatsMissingDirectoryAsNoFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "certs")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	publisher := NewPublisher(root, filepath.Join(t.TempDir(), "backups"))
	result, err := publisher.Backup("missing-certificate")
	if err != nil {
		t.Fatal(err)
	}
	if result.DirectoryExisted || result.BackupCreated {
		t.Fatalf("不存在的目录不应产生备份: %+v", result)
	}
	available, err := publisher.Available("missing-certificate")
	if err != nil {
		t.Fatal(err)
	}
	if len(available) != 0 {
		t.Fatalf("不存在的目录不应返回文件: %+v", available)
	}
}

func TestPublisherAvailableReturnsOnlyExistingSafeFiles(t *testing.T) {
	root := filepath.Join(t.TempDir(), "certs")
	target := filepath.Join(root, "partial-certificate")
	if err := os.MkdirAll(target, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "cert.pem"), []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	publisher := NewPublisher(root, filepath.Join(t.TempDir(), "backups"))
	available, err := publisher.Available("partial-certificate")
	if err != nil {
		t.Fatal(err)
	}
	if len(available) != 1 || !available["cert.pem"] {
		t.Fatalf("实际文件列表错误: %+v", available)
	}
	result, err := publisher.Backup("partial-certificate")
	if err == nil {
		t.Fatal("不完整目录必须拒绝备份")
	}
	if !result.DirectoryExisted || result.BackupCreated {
		t.Fatalf("备份结果错误: %+v", result)
	}
}
