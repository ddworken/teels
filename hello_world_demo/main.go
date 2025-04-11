package main

import (
	"io"
	"log"
	"net"
	"net/http"
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

func main() {
	rootHandler := func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello World!")
	}
	formatterHandler := func(w http.ResponseWriter, req *http.Request) {
		// if _, err := os.Stat("formatter.html"); os.IsNotExist(err) {
		// 	http.Error(w, "Service Unavailable - formatter.html not found", http.StatusServiceUnavailable)
		// 	return
		// }
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
