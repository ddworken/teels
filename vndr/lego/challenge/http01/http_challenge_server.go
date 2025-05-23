package http01

import (
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/log"
)

// ProviderServer implements ChallengeProvider for `http-01` challenge.
// It may be instantiated without using the NewProviderServer function if
// you want only to use the default values.
type ProviderServer struct {
	address string
	network string // must be valid argument to net.Listen

	socketMode fs.FileMode

	matcher         domainMatcher
	done            chan bool
	listener        net.Listener
	listenerCreator func() (net.Listener, error)
}

// NewProviderServer creates a new ProviderServer on the selected interface and port.
// Setting iface and / or port to an empty string will make the server fall back to
// the "any" interface and port 80 respectively.
func NewProviderServer(iface, port string) *ProviderServer {
	if port == "" {
		port = "80"
	}

	return &ProviderServer{network: "tcp", address: net.JoinHostPort(iface, port), matcher: &hostMatcher{}}
}

func NewUnixProviderServer(socketPath string, mode fs.FileMode) *ProviderServer {
	return &ProviderServer{network: "unix", address: socketPath, socketMode: mode, matcher: &hostMatcher{}}
}

func (s *ProviderServer) SetListenerCreator(listenerCreator func() (net.Listener, error)) {
	s.listenerCreator = listenerCreator
}

// Present starts a web server and makes the token available at `ChallengePath(token)` for web requests.
func (s *ProviderServer) Present(domain, token, keyAuth string) error {
	var err error
	if s.listenerCreator == nil {
		s.listener, err = net.Listen(s.network, s.GetAddress())
		if err != nil {
			return fmt.Errorf("could not start HTTP server for challenge: %w", err)
		}
	} else {
		s.listener, err = s.listenerCreator()
		if err != nil {
			return fmt.Errorf("could not start HTTP server for challenge: %w", err)
		}
	}

	if s.network == "unix" {
		if err = os.Chmod(s.address, s.socketMode); err != nil {
			return fmt.Errorf("chmod %s: %w", s.address, err)
		}
	}

	s.done = make(chan bool)

	go s.serve(domain, token, keyAuth)

	return nil
}

func (s *ProviderServer) GetAddress() string {
	return s.address
}

// CleanUp closes the HTTP server and removes the token from `ChallengePath(token)`.
func (s *ProviderServer) CleanUp(domain, token, keyAuth string) error {
	log.Infof("Cleaning up HTTP-01 challenge for domain %s", domain)
	if s.listener == nil {
		return nil
	}

	s.listener.Close()

	<-s.done

	return nil
}

// SetProxyHeader changes the validation of incoming requests.
// By default, s matches the "Host" header value to the domain name.
//
// When the server runs behind a proxy server, this is not the correct place to look at;
// Apache and NGINX have traditionally moved the original Host header into a new header named "X-Forwarded-Host".
// Other webservers might use different names;
// and RFC7239 has standardized a new header named "Forwarded" (with slightly different semantics).
//
// The exact behavior depends on the value of headerName:
// - "" (the empty string) and "Host" will restore the default and only check the Host header
// - "Forwarded" will look for a Forwarded header, and inspect it according to https://www.rfc-editor.org/rfc/rfc7239.html
// - any other value will check the header value with the same name.
func (s *ProviderServer) SetProxyHeader(headerName string) {
	switch h := textproto.CanonicalMIMEHeaderKey(headerName); h {
	case "", "Host":
		s.matcher = &hostMatcher{}
	case "Forwarded":
		s.matcher = &forwardedMatcher{}
	default:
		s.matcher = arbitraryMatcher(h)
	}
}

func (s *ProviderServer) serve(domain, token, keyAuth string) {
	path := ChallengePath(token)

	// The incoming request will be validated to prevent DNS rebind attacks.
	// We only respond with the keyAuth, when we're receiving a GET requests with
	// the "Host" header matching the domain (the latter is configurable though SetProxyHeader).
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && s.matcher.matches(r, domain) {
			w.Header().Set("Content-Type", "text/plain")

			_, err := w.Write([]byte(keyAuth))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			log.Infof("[%s] Served key authentication", domain)
			return
		}

		log.Warnf("Received request for domain %s with method %s but the domain did not match any challenge. Please ensure you are passing the %s header properly.", r.Host, r.Method, s.matcher.name())

		_, err := w.Write([]byte("TEST"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	httpServer := &http.Server{Handler: mux}

	// Once httpServer is shut down
	// we don't want any lingering connections, so disable KeepAlives.
	httpServer.SetKeepAlivesEnabled(false)

	err := httpServer.Serve(s.listener)
	if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		log.Println(err)
	}

	s.done <- true
}
