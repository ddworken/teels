package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/mdlayher/vsock"
)

// customFileServer wraps the standard FileServer to set correct MIME types
func customFileServer(root http.FileSystem) http.Handler {
	fs := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the file is a JavaScript file
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		fs.ServeHTTP(w, r)
	})
}

func rootHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("rootHandler")

	// Set content type to plain text
	w.Header().Set("Content-Type", "text/plain")

	// Walk through the /app directory
	err := filepath.Walk("/app", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Calculate indentation based on depth
		relPath, _ := filepath.Rel("/app", path)
		depth := strings.Count(relPath, string(filepath.Separator))
		indent := strings.Repeat("  ", depth)

		// Print file/directory name with appropriate prefix
		if info.IsDir() {
			io.WriteString(w, fmt.Sprintf("%s📁 %s/\n", indent, filepath.Base(path)))
		} else {
			io.WriteString(w, fmt.Sprintf("%s📄 %s\n", indent, filepath.Base(path)))
		}
		return nil
	})

	if err != nil {
		io.WriteString(w, fmt.Sprintf("Error listing files: %v\n", err))
	}
}

func main() {
	formatterHandler := func(w http.ResponseWriter, req *http.Request) {
		fmt.Println("formatterHandler")
		http.ServeFile(w, req, "/app/formatter.html")
	}

	// Create a new ServeMux
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/formatter", formatterHandler)

	// Serve static files with custom MIME type handling to fix a strict mime type checking error
	fs := customFileServer(http.Dir(filepath.Join("/app/", "static")))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	var listener net.Listener
	listener, err := net.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}

	if runtime.GOOS == "linux" {
		listener, err = vsock.Listen(80, nil)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Fatal(http.Serve(listener, mux))
}
