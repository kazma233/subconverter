package server

import _ "embed"

// indexHTML 订阅链接生成页，构建期内嵌进二进制（部署不依赖镜像外文件）。
//
//go:embed index.html
var indexHTML []byte
