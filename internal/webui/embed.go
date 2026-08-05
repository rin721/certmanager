// Package webui 嵌入前端生产构建产物。
package webui

import "embed"

// Assets 由 Vite 写入 dist；仓库保留最小占位页，使纯 Go 门禁无需先安装 Node 依赖。
//
//go:embed dist/*
var Assets embed.FS
