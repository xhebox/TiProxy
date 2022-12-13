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
	"github.com/lesismal/nbio"
	"github.com/pingcap/TiProxy/pkg/metrics"
	"github.com/pingcap/TiProxy/pkg/proxy/client"
	"go.uber.org/zap"
)

func (s *SQLServer) onOpen(conn *nbio.Conn) {
	s.mu.Lock()

	if s.mu.inShutdown {
		s.mu.Unlock()
		s.logger.Warn("in shutdown", zap.String("addr", conn.RemoteAddr().Network()), zap.Error(conn.Close()))
		return
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
		return
	}

	clientConn := client.NewClientConnection(logger.Named("conn"), s.certMgr.ServerTLS(), s.certMgr.SQLTLS(), s.hsHandler, connID, &client.BCConfig{
		ProxyProtocol:     s.mu.proxyProtocol,
		RequireBackendTLS: s.requireBackendTLS,
	})
	s.mu.clients[connID] = clientConn

	s.mu.Unlock()

	logger.Info("new connection")
	metrics.ConnGauge.Inc()

	conn.SetSession(clientConn)
}

func (s *SQLServer) onRead(c *nbio.Conn, data []byte) {
	clientConn := c.Session().(*client.ClientConnection)
}

func (s *SQLServer) onClose(c *nbio.Conn, e error) {
	clientConn := c.Session().(*client.ClientConnection)

	s.mu.Lock()
	delete(s.mu.clients, clientConn.ConnectionID())
	s.mu.Unlock()

	clientConn.Close()
	metrics.ConnGauge.Dec()
}
