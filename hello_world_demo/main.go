package main

import (
	"crypto/tls"
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
			if _, err := io.WriteString(w, fmt.Sprintf("%s📁 %s/\n", indent, filepath.Base(path))); err != nil {
				return err
			}
		} else {
			if _, err := io.WriteString(w, fmt.Sprintf("%s📄 %s\n", indent, filepath.Base(path))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if _, err := io.WriteString(w, fmt.Sprintf("Error listing files: %v\n", err)); err != nil {
			log.Printf("Error writing error message: %v", err)
		}
	}
}

func formatterHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("formatterHandler")

	// Check if the request is HTTP and redirect to HTTPS if needed
	if req.TLS == nil && req.Header.Get("X-Forwarded-Proto") != "https" {
		httpsURL := "https://" + req.Host + req.URL.Path
		http.Redirect(w, req, httpsURL, http.StatusMovedPermanently)
		return
	}

	http.ServeFile(w, req, "/app/formatter.html")
}

func main() {
	// Create a new ServeMux
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/formatter", formatterHandler)

	// Serve static files with custom MIME type handling to fix a strict mime type checking error
	fs := customFileServer(http.Dir(filepath.Join("/app/", "static")))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Start HTTP server
	go func() {
		var httpListener net.Listener
		var err error

		if runtime.GOOS == "linux" {
			httpListener, err = vsock.Listen(80, nil)
		} else {
			httpListener, err = net.Listen("tcp", ":80")
		}

		if err != nil {
			log.Fatal("HTTP server error:", err)
		}
		log.Println("HTTP server listening on port 80")
		log.Fatal(http.Serve(httpListener, mux))
	}()

	// Start HTTPS server
	go func() {
		// Load TLS certificates
		cert, err := tls.LoadX509KeyPair(
			"/app/output-keys/certificate.crt",
			"/app/output-keys/certificate_key.pem",
		)
		if err != nil {
			log.Fatal("Failed to load TLS certificates:", err)
		}

		// Configure TLS
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		var httpsListener net.Listener
		if runtime.GOOS == "linux" {
			httpsListener, err = vsock.Listen(443, nil)
		} else {
			httpsListener, err = net.Listen("tcp", ":443")
		}

		if err != nil {
			log.Fatal("HTTPS server error:", err)
		}

		// Wrap the listener with TLS
		tlsListener := tls.NewListener(httpsListener, tlsConfig)

		log.Println("HTTPS server listening on port 443")
		log.Fatal(http.Serve(tlsListener, mux))
	}()

	// Keep the main goroutine running
	select {}
}
