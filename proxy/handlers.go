package proxy

import (
	"log"
	"regexp"
	"strings"
	"sync"

	"github.com/etclabscore/open-etc-pool/rpc"
	"github.com/etclabscore/open-etc-pool/util"
)

var (
	noncePattern  = regexp.MustCompile("^0x[0-9a-f]{16}$")
	hashPattern   = regexp.MustCompile("^0x[0-9a-f]{64}$")
	workerPattern = regexp.MustCompile("^[0-9a-zA-Z-_]{1,8}$")
	addressCache  = sync.Map{} // Concurrent address cache
)

// Optimized login handler with caching
func (s *ProxyServer) handleLoginRPC(cs *Session, params []string, id string) (bool, *ErrorReply) {
	if len(params) == 0 {
		return false, &ErrorReply{Code: -1, Message: "Invalid params"}
	}

	login := strings.ToLower(params[0])

	// Fast path with cached validation
	if valid, ok := addressCache.Load(login); ok {
		if !valid.(bool) {
			return false, &ErrorReply{Code: -1, Message: "Invalid login"}
		}
	} else {
		valid := util.IsValidHexAddress(login)
		addressCache.Store(login, valid)
		if !valid {
			return false, &ErrorReply{Code: -1, Message: "Invalid login"}
		}
	}

	// Parallel policy check
	policyOk := make(chan bool, 1)
	go func() {
		policyOk <- s.policy.ApplyLoginPolicy(login, cs.ip)
	}()

	if !<-policyOk {
		return false, &ErrorReply{Code: -1, Message: "You are blacklisted"}
	}

	cs.login = login
	s.registerSession(cs)
	log.Printf("Stratum miner connected %v@%v", login, cs.ip)
	return true, nil
}

// Optimized work handler
func (s *ProxyServer) handleGetWorkRPC(cs *Session) ([]string, *ErrorReply) {
	t := s.currentBlockTemplate()
	if t == nil || len(t.Header) == 0 || s.isSick() {
		return nil, &ErrorReply{Code: 0, Message: "Work not ready"}
	}
	return []string{t.Header, t.Seed, s.diff}, nil
}

// Optimized submit handler with parallel validation
func (s *ProxyServer) handleTCPSubmitRPC(cs *Session, id string, params []string) (bool, *ErrorReply) {
	s.sessionsMu.RLock()
	_, ok := s.sessions[cs]
	s.sessionsMu.RUnlock()

	if !ok {
		return false, &ErrorReply{Code: 25, Message: "Not subscribed"}
	}

	// Fast validation
	if len(params) != 3 {
		s.policy.ApplyMalformedPolicy(cs.ip)
		return false, &ErrorReply{Code: -1, Message: "Invalid params"}
	}

	// Worker name processing
	if !workerPattern.MatchString(id) {
		id = "0"
	}

	// Parallel pattern validation
	var valid [3]bool
	var wg sync.WaitGroup
	wg.Add(3)

	validate := func(i int, pattern *regexp.Regexp, s string) {
		defer wg.Done()
		valid[i] = pattern.MatchString(s)
	}

	go validate(0, noncePattern, params[0])
	go validate(1, hashPattern, params[1])
	go validate(2, hashPattern, params[2])

	wg.Wait()

	if !valid[0] || !valid[1] || !valid[2] {
		s.policy.ApplyMalformedPolicy(cs.ip)
		return false, &ErrorReply{Code: -1, Message: "Malformed PoW result"}
	}

	t := s.currentBlockTemplate()
	exist, validShare := s.processShare(cs.login, id, cs.ip, t, params)
	ok = s.policy.ApplySharePolicy(cs.ip, !exist && validShare)

	if exist {
		return false, &ErrorReply{Code: 22, Message: "Duplicate share"}
	}

	if !validShare {
		if !ok {
			return false, &ErrorReply{Code: 23, Message: "Invalid share"}
		}
		return false, nil
	}

	if !ok {
		return true, &ErrorReply{Code: -1, Message: "High rate of invalid shares"}
	}
	return true, nil
}

// Optimized block handler
func (s *ProxyServer) handleGetBlockByNumberRPC() *rpc.GetBlockReplyPart {
	if t := s.currentBlockTemplate(); t != nil {
		return t.GetPendingBlockCache
	}
	return nil
}

func (s *ProxyServer) handleUnknownRPC(cs *Session, m string) *ErrorReply {
	s.policy.ApplyMalformedPolicy(cs.ip)
	return &ErrorReply{Code: -3, Message: "Method not found"}
}
