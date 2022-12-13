// Copyright 2022 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lesismal/nbio"
	"github.com/pingcap/TiProxy/lib/config"
	"github.com/pingcap/TiProxy/lib/util/waitgroup"
	"github.com/pingcap/TiProxy/pkg/manager/cert"
	"github.com/pingcap/TiProxy/pkg/proxy/client"
	"go.uber.org/zap"
)

type serverState struct {
	sync.RWMutex
	clients        map[uint64]*client.ClientConnection
	connID         uint64
	maxConnections uint64
	tcpKeepAlive   bool
	proxyProtocol  bool
	gracefulWait   int
	inShutdown     bool
}

type SQLServer struct {
	logger            *zap.Logger
	eng               *nbio.Engine
	certMgr           *cert.CertManager
	hsHandler         client.HandshakeHandler
	requireBackendTLS bool
	wg                waitgroup.WaitGroup
	cancelFunc        context.CancelFunc

	mu serverState
}

// NewSQLServer creates a new SQLServer.
func NewSQLServer(logger *zap.Logger, cfg config.ProxyServer, certMgr *cert.CertManager, hsHandler client.HandshakeHandler) (*SQLServer, error) {
	s := &SQLServer{
		logger:            logger,
		certMgr:           certMgr,
		hsHandler:         hsHandler,
		requireBackendTLS: cfg.RequireBackendTLS,
		eng: nbio.NewEngine(nbio.Config{
			Addrs: []string{
				fmt.Sprintf("tcp://%s", cfg.Addr),
			},
			NPoller:      1,
			LockListener: true,
			LockPoller:   true,
		}),
		mu: serverState{
			connID:  0,
			clients: make(map[uint64]*client.ClientConnection),
		},
	}

	s.reset(&cfg.ProxyServerOnline)

	s.eng.OnOpen(s.onOpen)
	s.eng.OnData(s.onRead)
	s.eng.OnClose(s.onClose)

	return s, nil
}

func (s *SQLServer) reset(cfg *config.ProxyServerOnline) {
	s.mu.Lock()
	s.mu.tcpKeepAlive = cfg.TCPKeepAlive
	s.mu.maxConnections = cfg.MaxConnections
	s.mu.proxyProtocol = cfg.ProxyProtocol != ""
	s.mu.gracefulWait = cfg.GracefulWaitBeforeShutdown
	s.mu.Unlock()
}

func (s *SQLServer) Run(ctx context.Context, cfgch <-chan *config.Config) {
	// Create another context because it still needs to run after graceful shutdown.
	ctx, s.cancelFunc = context.WithCancel(context.Background())

	s.wg.Run(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ach := <-cfgch:
				if ach == nil {
					// prevent panic on closing chan
					return
				}
				s.reset(&ach.Proxy.ProxyServerOnline)
			}
		}
	})

	s.logger.Info("run SQL server", zap.Error(s.eng.Start()))
}

// Graceful shutdown doesn't close the listener but rejects new connections.
// Whether this affects NLB is to be tested.
func (s *SQLServer) gracefulShutdown() {
	s.mu.Lock()
	gracefulWait := s.mu.gracefulWait
	if gracefulWait == 0 {
		s.mu.Unlock()
		return
	}
	s.mu.inShutdown = true
	for _, conn := range s.mu.clients {
		conn.GracefulClose()
	}
	s.mu.Unlock()
	s.logger.Info("SQL server is shutting down", zap.Int("graceful_wait", gracefulWait))

	timer := time.NewTimer(time.Duration(gracefulWait) * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			return
		case <-time.After(100 * time.Millisecond):
			s.mu.Lock()
			allClosed := len(s.mu.clients) == 0
			s.mu.Unlock()
			if allClosed {
				return
			}
		}
	}
}

// Close closes the server.
func (s *SQLServer) Close() error {
	s.gracefulShutdown()

	if s.cancelFunc != nil {
		s.cancelFunc()
		s.cancelFunc = nil
	}

	s.mu.Lock()
	for _, conn := range s.mu.clients {
		conn.Close()
	}
	s.mu.Unlock()

	s.eng.Stop()
	s.wg.Wait()
	return nil
}
