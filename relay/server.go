package relay

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/rstms/fetch-gmail/client"
	"golang.org/x/crypto/bcrypt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
)

const Version = "0.1.7"

const (
	SMTP_MAX_LINE = 1000
	ERROR_BUF     = 16
)

var MAIL_FROM_PATTERN = regexp.MustCompile(`^[mM][aA][iI][lL] [fF][rR][oO][mM]:<([^@]+@[^>]+)>.*$`)
var RCPT_TO_PATTERN = regexp.MustCompile(`^[rR][cC][pP][tT] [tT][oO]:<([^@]+@[^>]+)>.*$`)

type Server struct {
	Hostname           string
	Domain             string
	ListenHost         string
	Username           string
	PasswordHash       string
	stopRequest        chan struct{}
	stopRequestSent    bool
	handlerErr         chan error
	listenerErr        chan error
	listener           net.Listener
	acceptedConnection chan net.Conn
	verbose            bool
	debug              bool
	started            bool
	listenerClosing    bool
	cert               string
	key                string
	wg                 sync.WaitGroup
}

func NewServer(listenHost string) (*Server, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, Fatal(err)
	}
	if !strings.Contains(hostname, ".") {
	}
	_, domain, ok := strings.Cut(hostname, ".")
	if !ok {
		return nil, Fatalf("hostname not fqdn: %s", hostname)
	}
	s := Server{
		Hostname:           hostname,
		Domain:             domain,
		ListenHost:         listenHost,
		stopRequest:        make(chan struct{}, 1),
		acceptedConnection: make(chan net.Conn, 1),
		listenerErr:        make(chan error, ERROR_BUF),
		handlerErr:         make(chan error, ERROR_BUF),
		verbose:            ViperGetBool("verbose"),
		debug:              ViperGetBool("debug"),
		cert:               ViperGetString("smtp_server.cert"),
		key:                ViperGetString("smtp_server.key"),
		Username:           ViperGetString("smtp_server.username"),
		PasswordHash:       ViperGetString("smtp_server.password_hash"),
	}
	return &s, nil
}

func (s *Server) shutdown(caller string) {

	if s.listener != nil {
		log.Printf("shutdown[%s]: closing listener", caller)
		s.listenerClosing = true
		s.listener.Close()
		s.listener = nil
	} else {
		log.Printf("shutdown[%s]: listener already closed", caller)
	}

	if s.stopRequestSent {
		log.Printf("shutdown[%s]: stopRequest already sent", caller)
	} else {
		log.Printf("shutdown[%s]: sending stopRequest", caller)
		s.stopRequest <- struct{}{}
		s.stopRequestSent = true
	}
}

func (s *Server) listen(startChan chan struct{}) error {

	var startSent bool
	defer func() {
		if !startSent {
			startChan <- struct{}{}
		}
		s.shutdown("listen")
	}()
	if s.debug {
		log.Println("listener: started")
	}

	cert, err := tls.LoadX509KeyPair(s.cert, s.key)
	if err != nil {
		return Fatal(err)
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   "127.0.0.1",
	}

	listener, err := tls.Listen("tcp", s.ListenHost, config)
	if err != nil {
		return Fatal(err)
	}
	s.listener = listener
	startChan <- struct{}{}
	startSent = true
	log.Printf("listening for SMTP connections on: %v\n", listener.Addr())
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.listenerClosing {
				return nil
			}
			return Fatal(err)
		}
		s.acceptedConnection <- conn
	}
	return Fatalf("listener: unexpected exit")
}

func (s *Server) handler(startChan chan struct{}) error {
	defer s.shutdown("handler")
	if s.debug {
		log.Println("handler: started")
	}
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, syscall.SIGINT)
	sigterm := make(chan os.Signal, 1)
	signal.Notify(sigterm, syscall.SIGTERM)
	if s.verbose {
		fmt.Println("CTRL-C to exit")
	}
	startChan <- struct{}{}
	for {
		select {
		case <-sigint:
			if s.debug {
				log.Println("handler: received SIGINT")
			}
			return nil
		case <-sigterm:
			if s.debug {
				log.Println("handler: received SIGTERM")
			}
			return nil
		case _, ok := <-s.stopRequest:
			if ok {
				if s.debug {
					log.Println("handler: received stopRequest")
				}
				return nil
			} else {
				if s.debug {
					log.Println("handler: stopRequest has closed")
				}
				return nil
			}
		case conn, ok := <-s.acceptedConnection:
			if ok {
				err := s.smtpSession(conn)
				if err != nil {
					log.Printf("smtp session failed: %v\n", err)
				}
			} else {
				if s.debug {
					log.Println("handler: acceptedConnection has closed")
				}
				return nil
			}
		}
	}
	return Fatalf("unexpected exit")
}

func (s *Server) Start() error {
	defer func() {
		s.started = true
	}()
	if s.started {
		return Fatalf("already started")
	}
	listenerStarted := make(chan struct{})
	go func() {
		s.wg.Add(1)
		defer s.wg.Done()
		s.listenerErr <- s.listen(listenerStarted)
	}()
	<-listenerStarted

	handlerStarted := make(chan struct{})
	go func() {
		s.wg.Add(1)
		defer s.wg.Done()
		s.handlerErr <- s.handler(handlerStarted)
	}()
	<-handlerStarted
	return nil
}

func (s *Server) Run() error {
	err := s.Start()
	if err != nil {
		return Fatal(err)
	}
	err = s.Wait()
	if err != nil {
		return Fatal(err)
	}
	return nil
}

func (s *Server) Wait() error {
	defer func() {
		close(s.listenerErr)
		close(s.handlerErr)
		close(s.acceptedConnection)
		close(s.stopRequest)
	}()
	if s.debug {
		log.Println("wait: waiting on goprocs...")
	}
	s.wg.Wait()
	if s.debug {
		log.Println("wait: all goprocs have exited")
	}
	var ret error
	for done := false; !done; {
		select {
		case err, ok := <-s.listenerErr:
			if ok {
				if err != nil {
					if ret == nil {
						ret = err
					} else {
						log.Printf("listener: %v\n", err)
					}
				}
			}
		case err, ok := <-s.handlerErr:
			if ok {
				if err != nil {
					if ret == nil {
						ret = err
					} else {
						log.Printf("handler: %v\n", err)
					}
				}
			}
		default:
			done = true
		}
	}
	return ret
}

func (s *Server) Stop(wait bool) error {
	s.shutdown("stop")
	if wait {
		err := s.Wait()
		if err != nil {
			return Fatal(err)
		}
	}
	return nil
}

func (s *Server) smtpSend(conn net.Conn, code int, format string, args ...interface{}) error {
	line := fmt.Sprintf(format, args...)
	if code != 0 {
		line = fmt.Sprintf("%03d %s", code, line)
	}
	if s.debug {
		log.Printf("TX: %s\n", line)
	}
	_, err := io.WriteString(conn, line+"\r\n")
	if err != nil {
		return Fatal(err)
	}
	return nil
}

func (s *Server) smtpReceive(conn net.Conn) (string, error) {
	buf := make([]byte, SMTP_MAX_LINE+1)
	n, err := conn.Read(buf)
	if err != nil {
		return "", Fatal(err)
	}
	if n > SMTP_MAX_LINE {
		return "", Fatalf("line buffer overflow")
	}
	line := strings.TrimSpace(string(buf[:n]))
	if s.debug {
		log.Printf("RX: %s\n", line)
	}
	return line, nil
}

func (s *Server) cmdField(conn net.Conn, fields []string, index int, match string) (string, error) {
	switch {
	case len(fields) < index+1:
	case fields[index] == "":
	case match == "" || fields[index] == match:
		return fields[index], nil
	}
	return "", s.smtpSendSyntaxError(conn, fields)
}

func (s *Server) smtpSendSyntaxError(conn net.Conn, fields []string) error {
	err := s.smtpSend(conn, 501, "5.5.1 Syntax error in parameters or arguments")
	if err != nil {
		return Fatal(err)
	}
	return fmt.Errorf("smtp: client syntax error: '%v'", fields)
}

func (s *Server) smtpSession(conn net.Conn) error {
	defer func() {
		err := s.smtpSend(conn, 221, "Bye")
		if err != nil {
			log.Printf("smtp: final write failed: %v", Fatal(err))
		}
		err = conn.Close()
		if err != nil {
			log.Printf("%v\n", Fatal(err))
		}
	}()
	err := s.smtpSend(conn, 220, "%s ESMTP Server", s.Domain)
	if err != nil {
		return Fatal(err)
	}
	remote := conn.RemoteAddr()
	if s.verbose {
		log.Printf("smtp: session started for %s\n", remote)
	}
	remoteAddr, _, ok := strings.Cut(remote.String(), ":")
	if !ok {
		return Fatalf("failed parsing remoteAddr '%s'", remote)
	}
	if remoteAddr != "127.0.0.1" {
		err := s.smtpSend(conn, 550, "remote connections are not allowed here")
		if err != nil {
			return Fatal(err)
		}
		return Fatalf("remote connection denied: %s", remote)
	}
	authorized := false
	var clientHost string
	var mailFrom string
	rcptTo := []string{}
	for done := false; !done; {
		line, err := s.smtpReceive(conn)
		if err != nil {
			return Fatal(err)
		}
		command, _, _ := strings.Cut(line, " ")
		command = strings.ToUpper(command)
		switch command {
		case "EHLO":
			fields := strings.Split(line, " ")
			clientHost, err := s.cmdField(conn, fields, 1, "")
			if err != nil {
				return Fatal(err)
			}
			err = s.smtpSend(conn, 0, "250-%s Hello %s", s.Domain, clientHost)
			if err != nil {
				return Fatal(err)
			}
			err = s.smtpSend(conn, 250, "AUTH PLAIN")
			if err != nil {
				return Fatal(err)
			}
		case "MAIL":
			err := s.CheckAuth(conn, "MAIL", authorized)
			if err != nil {
				return Fatal(err)
			}
			fields := MAIL_FROM_PATTERN.FindStringSubmatch(line)
			if len(fields) == 2 {
				mailFrom = fields[1]
				err = s.smtpSend(conn, 250, "Ok")
				if err != nil {
					return Fatal(err)
				}
			} else {
				return s.smtpSendSyntaxError(conn, []string{line})
			}
		case "RCPT":
			err := s.CheckAuth(conn, "RCPT", authorized)
			if err != nil {
				return Fatal(err)
			}
			fields := RCPT_TO_PATTERN.FindStringSubmatch(line)
			if len(fields) == 2 {
				rcptTo = append(rcptTo, fields[1])
				err = s.smtpSend(conn, 250, "Ok")
				if err != nil {
					return Fatal(err)
				}
			} else {
				return s.smtpSendSyntaxError(conn, []string{line})
			}

		case "AUTH":
			authorized, err = s.DoAuth(conn, strings.Split(line, " "))
			if err != nil {
				return Fatal(err)
			}
		case "DATA":
			err := s.CheckAuth(conn, "DATA", authorized)
			if err != nil {
				return Fatal(err)
			}
			if mailFrom == "" {
				err := s.smtpSend(conn, 503, "command out of sequence")
				if err != nil {
					return Fatal(err)
				}
				return Fatalf("client sent DATA without MAIL FROM")
			}
			if len(rcptTo) == 0 {
				err := s.smtpSend(conn, 554, "no valid recipients")
				if err != nil {
					return Fatal(err)
				}
				return Fatalf("client sent DATA without RCPT TO")
			}
			err = s.smtpSend(conn, 354, "start data, end with <CRLF>.<CRLF>")
			if err != nil {
				return Fatal(err)
			}
			if s.verbose {
				log.Printf("smtp: starting relay...\n")
			}
			code, msg, err := s.DoRelay(conn, clientHost, mailFrom, rcptTo)
			if err != nil {
				log.Printf("smtp: relay failed: %v", err)
			}
			err = s.smtpSend(conn, code, "%s", msg)
			if err != nil {
				return Fatal(err)
			}
			if s.verbose {
				log.Printf("smtp: relay complete\n")
			}
		case "QUIT":
			if s.verbose {
				log.Printf("smtp: received QUIT\n")
			}
			return nil
		default:
			err := s.smtpSend(conn, 500, "5.5.1 command unrecognized")
			if err != nil {
				return Fatal(err)
			}
			return Fatalf("received unexpected command '%s'\n", line)
		}
	}
	return Fatalf("unexpected exit")
}

func (s *Server) DoRelay(conn net.Conn, clientHost, mailFrom string, rcptTo []string) (int, string, error) {
	relay, err := client.NewRelay(clientHost, mailFrom, rcptTo)
	if err != nil {
		return 550, "internal error", Fatal(err)
	}
	code, msg, err := relay.Send(conn)
	if err != nil {
		return code, msg, Fatal(err)
	}
	return code, msg, nil
}

func (s *Server) CheckAuth(conn net.Conn, command string, authorized bool) error {
	if authorized {
		return nil
	}
	err := s.smtpSend(conn, 530, "5.7.0 Authentication required")
	if err != nil {
		return Fatal(err)
	}
	return Fatalf("%s without AUTH, terminating\n", command)
}

func (s *Server) DoAuth(conn net.Conn, fields []string) (bool, error) {
	authType, err := s.cmdField(conn, fields, 1, "")
	if err != nil {
		return false, Fatal(err)
	}
	if authType != "PLAIN" {
		s.smtpSend(conn, 502, "5.5.1 unsupported authentication type")
		return false, Fatalf("client requested unsupported AUTH type: '%s'", authType)
	}
	encoded, err := s.cmdField(conn, fields, 2, "")
	if err != nil {
		return false, Fatal(err)
	}
	authFields := []string{}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err == nil {
		authFields = strings.Split(string(decoded), "\000")
	} else {
		log.Printf("%v\n", Fatal(err))
	}
	switch {
	case len(authFields) != 3:
	case authFields[0] != "":
	case authFields[1] == "":
	case authFields[2] == "":
	default:
		username := authFields[1]
		password := authFields[2]
		valid, err := s.validatePassword(username, password)
		if err != nil {
			log.Printf("%v\n", Fatal(err))
		}
		if valid {
			err = s.smtpSend(conn, 235, "2.7.0 Authentication successful")
			if err != nil {
				return false, Fatal(err)
			}
			log.Printf("smtp: client auth success for '%s'\n", username)
			return true, nil
		}
		err = s.smtpSend(conn, 535, "5.7.8 authorization failed")
		if err != nil {
			return false, Fatal(err)
		}
		return false, Fatalf("client auth failed for '%s'", username)

	}
	err = s.smtpSend(conn, 535, "5.7.8 failed decoding authentication credential")
	if err != nil {
		return false, Fatal(err)
	}
	return false, Fatalf("client auth decode failed")
}

func (s *Server) validatePassword(username, password string) (bool, error) {
	log.Printf("arg username=%s\n", username)
	log.Printf("arg password=%s\n", password)
	log.Printf("s.Username=%s\n", s.Username)
	log.Printf("s.PasswordHash=%s\n", s.PasswordHash)
	if username != s.Username {
		return false, Fatalf("username mismatch")
	}
	hashbuf, err := base64.StdEncoding.DecodeString(s.PasswordHash)
	if err != nil {
		return false, Fatal(err)
	}
	err = bcrypt.CompareHashAndPassword(hashbuf, []byte(password))
	if err != nil {
		return false, Fatal(err)
	}
	return true, nil
}
