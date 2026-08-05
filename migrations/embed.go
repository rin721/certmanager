// Package migrations 嵌入 SQLite 迁移文件，发布二进制无需额外复制 SQL。
package migrations

import "embed"

// FS 包含 goose 使用的版本化迁移。
//
//go:embed *.sql
var FS embed.FS
