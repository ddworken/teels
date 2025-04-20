package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ddworken/teels/lib"

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

func cyberchefHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("cyberchefHandler")

	// Check if the request is HTTP and redirect to HTTPS if needed
	if req.TLS == nil && req.Header.Get("X-Forwarded-Proto") != "https" && isNitroEnvironment() {
		httpsURL := "https://" + req.Host + req.URL.Path
		http.Redirect(w, req, httpsURL, http.StatusMovedPermanently)
		return
	}

	http.Redirect(w, req, "/static/cyberchef/index.html", http.StatusMovedPermanently)
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

// osFS implements the FileSystem interface for real file system operations
type osFS struct{}

func (osFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name)
}

func (osFS) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(name, data, perm)
}

func (osFS) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func attestationHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Println("attestationHandler")

	// Check if the request is HTTP and redirect to HTTPS if needed
	if req.TLS == nil && req.Header.Get("X-Forwarded-Proto") != "https" && isNitroEnvironment() {
		httpsURL := "https://" + req.Host + req.URL.Path
		http.Redirect(w, req, httpsURL, http.StatusMovedPermanently)
		return
	}

	// Read version file
	version := "N/A"
	versionBytes, err := os.ReadFile(filepath.Join(baseDir, "static", "VERSION"))
	if err == nil {
		version = strings.TrimSpace(string(versionBytes))
	}

	// Read attestation file
	attestation := "N/A"
	attestationDir := filepath.Join(baseDir, "static", "output-attestations")
	files, err := os.ReadDir(attestationDir)
	if err == nil && len(files) > 0 {
		attestationBytes, err := os.ReadFile(filepath.Join(attestationDir, files[0].Name()))
		if err == nil {
			attestation = string(attestationBytes)
		}
	}

	// Parse attestation document
	var attestationReport lib.AttestationReport
	if err := json.Unmarshal([]byte(attestation), &attestationReport); err == nil {
		// Get validated attestation document
		doc, err := lib.GetValidatedAttestationDoc(string(attestationReport.AwsNitroAttestation), osFS{})
		if err == nil {
			// Format timestamp
			timestamp := time.UnixMilli(int64(doc.TimeStamp)).Format(time.RFC3339)

			// Format user data
			userData := fmt.Sprintf("%x", doc.User_Data)

			// Format PCR data for templating
			type PCRData struct {
				Index int32
				Value string
			}
			var pcrData []PCRData
			for i, pcr := range doc.PCRs {
				pcrData = append(pcrData, PCRData{
					Index: int32(i),
					Value: fmt.Sprintf("%x", pcr),
				})
			}
			// Sort pcrData by Index in ascending order
			sort.Slice(pcrData, func(i, j int) bool {
				return pcrData[i].Index < pcrData[j].Index
			})

			// Set content type to HTML
			w.Header().Set("Content-Type", "text/html")

			// Define template data
			data := struct {
				Version     string
				Attestation string
				PCRs        []PCRData
				Timestamp   string
				UserData    string
			}{
				Version:     version,
				Attestation: attestation,
				PCRs:        pcrData,
				Timestamp:   timestamp,
				UserData:    userData,
			}

			// Create and parse template
			tmpl := template.Must(template.New("attestation").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Teels Attestation</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .section {
            margin-bottom: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        pre {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
            max-width: 100%;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
            table-layout: fixed;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background-color: #f5f5f5;
        }
        td pre {
            max-height: 200px;
            overflow-y: auto;
            margin: 0;
        }
    </style>
</head>
<body>
    <div class="section">
        <h2>Github Link</h2>
        <p><a href="https://github.com/ddworken/teels">github.com/ddworken/teels</a></p>
    </div>
    
    <div class="section">
        <h2>Deployed Version</h2>
        <p>v0.{{.Version}}</p>
    </div>

    <div class="section">
        <h2>Attestation Details</h2>
        <h3>Timestamp</h3>
        <p>{{.Timestamp}}</p>
        <h3>User Data</h3>
        <p><pre>{{.UserData}}</pre></p>
        <h3>PCRs</h3>
        <table border='1'>
            <tr><th>PCR Index</th><th>Value (hex)</th></tr>
            {{range .PCRs}}
            <tr><td>{{.Index}}</td><td><pre>{{.Value}}</pre></td></tr>
            {{end}}
        </table>
    </div>
    
    <div class="section">
        <h2>Raw Attestation</h2>
        <pre>{{.Attestation}}</pre>
    </div>
</body>
</html>
`))

			// Execute template
			if err := tmpl.Execute(w, data); err != nil {
				log.Printf("Error executing template: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
			return
		}
	}

	// If we get here, either the attestation couldn't be parsed or validated
	// Set content type to HTML
	w.Header().Set("Content-Type", "text/html")

	// Define template data
	data := struct {
		Version     string
		Attestation string
	}{
		Version:     version,
		Attestation: attestation,
	}

	// Create and parse template
	tmpl := template.Must(template.New("attestation").Parse(`
<!DOCTYPE html>
<html>
<head>
    <title>Teels Attestation</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .section {
            margin-bottom: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
        }
        pre {
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 3px;
            overflow-x: auto;
            max-width: 100%;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <div class="section">
        <h2>Github Link</h2>
        <p><a href="https://github.com/ddworken/teels">github.com/ddworken/teels</a></p>
    </div>
    
    <div class="section">
        <h2>Deployed Version</h2>
        <p>v0.{{.Version}}</p>
    </div>
    
    <div class="section">
        <h2>Raw Attestation</h2>
        <pre>{{.Attestation}}</pre>
    </div>
</body>
</html>
`))

	// Execute template
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func rootHandler(w http.ResponseWriter, req *http.Request) {
	// Only serve index.html if the path is exactly "/"
	if req.URL.Path == "/" {
		// Check if the request is HTTP and redirect to HTTPS if needed
		if req.TLS == nil && req.Header.Get("X-Forwarded-Proto") != "https" && isNitroEnvironment() {
			httpsURL := "https://" + req.Host + req.URL.Path
			http.Redirect(w, req, httpsURL, http.StatusMovedPermanently)
			return
		}

		http.ServeFile(w, req, filepath.Join(baseDir, "index.html"))
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
	mux.HandleFunc("/cyberchef", cyberchefHandler)
	mux.HandleFunc("/diffchecker", diffCheckerHandler)
	mux.HandleFunc("/attestation", attestationHandler)

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
