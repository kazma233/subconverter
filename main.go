// subconv 入口：启动 HTTP 服务。
// 监听端口默认 25600，可用环境变量 PORT 覆盖。
// 日志目的地由 SUBCONV_ENV 决定：production 写 LOG_FILE 文件（追加写入），
// 其余值或未设置为 dev，输出控制台。
package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"subconv/internal/server"
)

// defaultLogFile production 模式下 LOG_FILE 未设置时的默认日志路径，
// 与 docker-compose 命名卷挂载点一致，部署无需显式配置。
const defaultLogFile = "/var/log/subconv/subconv.log"

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "25600"
	}
	addr := ":" + port

	logDest := "控制台"
	if os.Getenv("SUBCONV_ENV") == "production" {
		path := os.Getenv("LOG_FILE")
		if path == "" {
			path = defaultLogFile
		}
		if dir := filepath.Dir(path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				log.Fatalf("创建日志目录 %s 失败: %v", dir, err)
			}
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("打开日志文件 %s 失败: %v", path, err)
		}
		defer f.Close()
		log.SetOutput(f)
		logDest = "文件 " + path
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           server.NewHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("subconv %s 监听 %s（日志输出: %s）", server.Version, addr, logDest)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
