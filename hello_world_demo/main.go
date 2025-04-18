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
	"strings"

	"github.com/mdlayher/vsock"
)

var baseDir string

func init() {
	if isNitroEnvironment() {
		baseDir = "/app/"
	} else {
		var err error
		baseDir, err = os.Getwd()
		if err != nil {
			log.Fatalf("Failed to get current working directory: %v", err)
		}
		// Ensure baseDir ends with a separator for consistency
		if !strings.HasSuffix(baseDir, string(filepath.Separator)) {
			baseDir += string(filepath.Separator)
		}
	}
	log.Printf("Base directory set to: %s", baseDir)
}

// isNitroEnvironment checks if the AWS_NITRO environment variable is set.
func isNitroEnvironment() bool {
	return os.Getenv("AWS_NITRO") != ""
}

// customFileServer wraps the standard FileServer to set correct MIME types
func customFileServer(root http.FileSystem) http.Handler {
	fs := http.FileServer(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if the file is a JavaScript file
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		// Check if the file is a CSS file
		if strings.HasSuffix(r.URL.Path, ".css") {
			w.Header().Set("Content-Type", "text/css")
		}
		fs.ServeHTTP(w, r)
	})
}

func debugHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("debugHandler")

	// Set content type to plain text
	w.Header().Set("Content-Type", "text/plain")

	// Walk through the base directory
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Calculate indentation based on depth
		relPath, _ := filepath.Rel(baseDir, path)
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
	if req.TLS == nil && req.Header.Get("X-Forwarded-Proto") != "https" && isNitroEnvironment() {
		httpsURL := "https://" + req.Host + req.URL.Path
		http.Redirect(w, req, httpsURL, http.StatusMovedPermanently)
		return
	}

	http.ServeFile(w, req, filepath.Join(baseDir, "formatter.html"))
}

// Add a handler for the new diff checker page
func diffCheckerHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("diffCheckerHandler")

	// Check if the request is HTTP and redirect to HTTPS if needed
	if req.TLS == nil && req.Header.Get("X-Forwarded-Proto") != "https" && isNitroEnvironment() {
		httpsURL := "https://" + req.Host + req.URL.Path
		http.Redirect(w, req, httpsURL, http.StatusMovedPermanently)
		return
	}

	http.ServeFile(w, req, filepath.Join(baseDir, "diffchecker.html"))
}

func rootHandler(w http.ResponseWriter, req *http.Request) {
	// Only redirect if the path is exactly "/"
	if req.URL.Path == "/" {
		http.Redirect(w, req, "/formatter", http.StatusMovedPermanently)
		return
	}
	// For any other path, return 404
	http.NotFound(w, req)
}

func main() {
	// Create a new ServeMux
	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/debug", debugHandler)
	mux.HandleFunc("/formatter", formatterHandler)
	mux.HandleFunc("/diffchecker", diffCheckerHandler)

	// Serve static files with custom MIME type handling to fix a strict mime type checking error
	fs := customFileServer(http.Dir(filepath.Join(baseDir, "static")))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Start HTTP server
	go func() {
		var httpListener net.Listener
		var err error

		if isNitroEnvironment() {
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
	if isNitroEnvironment() {
		go func() {
			// Load TLS certificates
			cert, err := tls.LoadX509KeyPair(
				filepath.Join(baseDir, "output-keys", "certificate.crt"),
				filepath.Join(baseDir, "output-keys", "certificate_key.pem"),
			)
			if err != nil {
				log.Fatal("Failed to load TLS certificates:", err)
			}

			// Configure TLS
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
			}

			var httpsListener net.Listener
			httpsListener, err = vsock.Listen(443, nil)
			if err != nil {
				log.Fatal("HTTPS server error:", err)
			}

			// Wrap the listener with TLS
			tlsListener := tls.NewListener(httpsListener, tlsConfig)

			log.Println("HTTPS server listening on port 443")
			log.Fatal(http.Serve(tlsListener, mux))
		}()
	}

	// Keep the main goroutine running
	select {}
}
