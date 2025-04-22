package proxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/etclabscore/open-etc-pool/util"
)

const (
	MaxReqSize         = 1024
	DefaultPingTimeout = 90 * time.Second
	MaxConcurrentSends = 500
)

func (s *ProxyServer) ListenTCP() {
	timeout := util.MustParseDuration(s.config.Proxy.Stratum.Timeout)
	s.timeout = timeout

	addr, err := net.ResolveTCPAddr("tcp4", s.config.Proxy.Stratum.Listen)
	if err != nil {
		log.Fatalf("Error resolving address: %v", err)
	}

	server, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		log.Fatalf("Error listening: %v", err)
	}
	defer server.Close()

	log.Printf("Stratum listening on %s", s.config.Proxy.Stratum.Listen)

	var acceptSem = make(chan struct{}, s.config.Proxy.Stratum.MaxConn)
	go s.sessionCleaner()

	for {
		conn, err := server.AcceptTCP()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(30 * time.Second)
		conn.SetNoDelay(true)

		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

		if s.policy.IsBanned(ip) || !s.policy.ApplyLimitPolicy(ip) {
			conn.Close()
			continue
		}

		acceptSem <- struct{}{}
		cs := &Session{
			conn:         conn,
			ip:           ip,
			enc:          json.NewEncoder(conn),
			lastActivity: time.Now(),
			pingTimeout:  DefaultPingTimeout,
		}

		go func() {
			defer func() { <-acceptSem }()
			err := s.handleTCPClient(cs)
			if err != nil {
				s.removeSession(cs)
				conn.Close()
			}
		}()
	}
}

func (s *ProxyServer) sessionCleaner() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		s.cleanInactiveSessions()
	}
}

func (s *ProxyServer) cleanInactiveSessions() {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	now := time.Now()
	for cs := range s.sessions {
		if now.Sub(cs.lastActivity) > cs.pingTimeout {
			cs.conn.Close()
			delete(s.sessions, cs)
		}
	}
}

func (s *ProxyServer) handleTCPClient(cs *Session) error {
	s.registerSession(cs)
	connbuff := bufio.NewReaderSize(cs.conn, MaxReqSize)

	for {
		s.setDeadline(cs.conn)
		data, isPrefix, err := connbuff.ReadLine()
		if isPrefix {
			log.Printf("Socket flood detected from %s", cs.ip)
			s.policy.BanClient(cs.ip)
			return err
		} else if err == io.EOF {
			log.Printf("Client %s disconnected", cs.ip)
			break
		} else if err != nil {
			log.Printf("Error reading from socket: %v", err)
			return err
		}

		if len(data) > 1 {
			cs.lastActivity = time.Now()
			var req StratumReq
			if err := json.Unmarshal(data, &req); err != nil {
				s.policy.ApplyMalformedPolicy(cs.ip)
				log.Printf("Malformed stratum request from %s: %v", cs.ip, err)
				return err
			}
			if err := cs.handleTCPMessage(s, &req); err != nil {
				return err
			}
		}
	}
	return nil
}

func (cs *Session) handleTCPMessage(s *ProxyServer, req *StratumReq) error {
	switch req.Method {
	case "eth_submitLogin":
		var params []string
		if err := json.Unmarshal(req.Params, &params); err != nil {
			log.Println("Malformed login params from", cs.ip)
			return err
		}
		reply, errReply := s.handleLoginRPC(cs, params, req.Worker)
		if errReply != nil {
			return cs.sendTCPError(req.Id, errReply)
		}
		return cs.sendTCPResult(req.Id, reply)

	case "eth_getWork":
		reply, errReply := s.handleGetWorkRPC(cs)
		if errReply != nil {
			return cs.sendTCPError(req.Id, errReply)
		}
		return cs.sendTCPResult(req.Id, &reply)

	case "eth_submitWork":
		var params []string
		if err := json.Unmarshal(req.Params, &params); err != nil {
			log.Println("Malformed work submission from", cs.ip)
			return err
		}
		reply, errReply := s.handleTCPSubmitRPC(cs, req.Worker, params)
		if errReply != nil {
			return cs.sendTCPError(req.Id, errReply)
		}
		return cs.sendTCPResult(req.Id, &reply)

	case "eth_submitHashrate":
		return cs.sendTCPResult(req.Id, true)

	case "mining.ping":
		var params []string
		if err := json.Unmarshal(req.Params, &params); err != nil || len(params) == 0 {
			return cs.sendTCPError(req.Id, &ErrorReply{Code: -1, Message: "Invalid ping"})
		}
		cs.lastPing = time.Now()
		return cs.sendTCPResult(req.Id, map[string]string{"pong": params[0]})

	default:
		errReply := s.handleUnknownRPC(cs, req.Method)
		return cs.sendTCPError(req.Id, errReply)
	}
}

func (cs *Session) sendTCPResult(id json.RawMessage, result interface{}) error {
	cs.Lock()
	defer cs.Unlock()

	message := JSONRpcResp{Id: id, Version: "2.0", Error: nil, Result: result}
	return cs.enc.Encode(&message)
}

func (cs *Session) pushNewJob(result interface{}) error {
	cs.Lock()
	defer cs.Unlock()

	message := JSONPushMessage{Version: "2.0", Result: result, Id: 0}
	return cs.enc.Encode(&message)
}

func (cs *Session) sendTCPError(id json.RawMessage, reply *ErrorReply) error {
	cs.Lock()
	defer cs.Unlock()

	message := JSONRpcResp{Id: id, Version: "2.0", Error: reply}
	err := cs.enc.Encode(&message)
	if err != nil {
		return err
	}
	return errors.New(reply.Message)
}

func (s *ProxyServer) setDeadline(conn *net.TCPConn) {
	timeout := s.timeout
	if len(s.sessions) > 1000 {
		timeout = timeout / 2
	}
	conn.SetDeadline(time.Now().Add(timeout))
}

func (s *ProxyServer) registerSession(cs *Session) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	s.sessions[cs] = struct{}{}
}

func (s *ProxyServer) removeSession(cs *Session) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if _, ok := s.sessions[cs]; ok {
		delete(s.sessions, cs)
	}
}

func (s *ProxyServer) broadcastNewJobs() {
	t := s.currentBlockTemplate()
	if t == nil || len(t.Header) == 0 || s.isSick() {
		return
	}
	reply := []string{t.Header, t.Seed, s.diff}

	s.sessionsMu.RLock()
	sessions := make([]*Session, 0, len(s.sessions))
	for m := range s.sessions {
		sessions = append(sessions, m)
	}
	s.sessionsMu.RUnlock()

	log.Printf("Broadcasting new job to %v stratum miners", len(sessions))

	start := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, MaxConcurrentSends)

	for _, cs := range sessions {
		wg.Add(1)
		sem <- struct{}{}

		go func(cs *Session) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := cs.pushNewJob(&reply); err != nil {
				log.Printf("Job transmit error to %v@%v: %v", cs.login, cs.ip, err)
				s.removeSession(cs)
				cs.conn.Close()
			} else {
				s.setDeadline(cs.conn)
			}
		}(cs)
	}

	wg.Wait()
	log.Printf("Jobs broadcast finished %s", time.Since(start))
}
