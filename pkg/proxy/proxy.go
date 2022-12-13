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

	"github.com/panjf2000/ants"
	"github.com/panjf2000/gnet/v2"
	"github.com/pingcap/TiProxy/lib/config"
	"github.com/pingcap/TiProxy/lib/util/waitgroup"
	"github.com/pingcap/TiProxy/pkg/manager/cert"
	"github.com/pingcap/TiProxy/pkg/metrics"
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
	gnet.BuiltinEventEngine

	logger            *zap.Logger
	eng               gnet.Engine
	certMgr           *cert.CertManager
	addr              string
	hsHandler         client.HandshakeHandler
	requireBackendTLS bool
	wg                waitgroup.WaitGroup
	cancelFunc        context.CancelFunc

	conns *ants.Pool

	mu serverState
}

// NewSQLServer creates a new SQLServer.
func NewSQLServer(logger *zap.Logger, cfg config.ProxyServer, certMgr *cert.CertManager, hsHandler client.HandshakeHandler) (*SQLServer, error) {
	s := &SQLServer{
		logger:            logger,
		certMgr:           certMgr,
		hsHandler:         hsHandler,
		requireBackendTLS: cfg.RequireBackendTLS,
		mu: serverState{
			connID:  0,
			clients: make(map[uint64]*client.ClientConnection),
		},
	}

	s.reset(&cfg.ProxyServerOnline)

	s.addr = fmt.Sprintf("tcp://%s", cfg.Addr)

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

	s.wg.Run(func() {
		opts := []gnet.Option{
			gnet.WithLockOSThread(true),
			gnet.WithMulticore(true),
			gnet.WithLogger(s.logger.Sugar()),
		}
		s.logger.Info("run SQL server", zap.Error(gnet.Run(s, s.addr, opts...)))
	})
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

	s.eng.Stop(context.TODO())

	s.wg.Wait()
	return nil
}

func (s *SQLServer) OnBoot(eng gnet.Engine) gnet.Action {
	s.eng = eng
	return gnet.None
}

func (s *SQLServer) OnOpen(conn gnet.Conn) ([]byte, gnet.Action) {
	s.mu.Lock()

	if s.mu.inShutdown {
		s.mu.Unlock()
		s.logger.Warn("in shutdown", zap.String("addr", conn.RemoteAddr().Network()), zap.Error(conn.Close()))
		return nil, gnet.Close
	}

	conns := uint64(len(s.mu.clients))
	maxConns := s.mu.maxConnections

	connID := s.mu.connID
	logger := s.logger.With(zap.Uint64("connID", connID), zap.String("remoteAddr", conn.RemoteAddr().String()))
	s.mu.connID++

	// 'maxConns == 0' => unlimited connections
	if maxConns != 0 && conns >= maxConns {
		s.mu.Unlock()
		s.logger.Warn("too many connections", zap.Uint64("max connections", maxConns), zap.Error(conn.Close()))
		return nil, gnet.Close
	}

	clientConn := client.NewClientConnection(logger.Named("conn"), s.certMgr.ServerTLS(), s.certMgr.SQLTLS(), s.hsHandler, connID, &client.BCConfig{
		ProxyProtocol:     s.mu.proxyProtocol,
		RequireBackendTLS: s.requireBackendTLS,
	})
	s.mu.clients[connID] = clientConn

	s.mu.Unlock()

	logger.Info("new connection")
	metrics.ConnGauge.Inc()

	conn.SetContext(clientConn)
	// TODO: check error
	conn.Wake(func(c gnet.Conn, err error) error { return nil })
	return nil, gnet.None
}

func (s *SQLServer) OnTraffic(c gnet.Conn) gnet.Action {
	ctx := c.Context()
	ctx.(*client.ClientConnection).OnTraffic(c)
	return gnet.None
}

func (s *SQLServer) OnClose(c gnet.Conn, e error) gnet.Action {
	clientConn := c.Context().(*client.ClientConnection)

	s.mu.Lock()
	delete(s.mu.clients, clientConn.ConnectionID())
	s.mu.Unlock()

	clientConn.Close()
	metrics.ConnGauge.Dec()

	return gnet.Close
}
