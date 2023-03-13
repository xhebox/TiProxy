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

package client

import (
	"context"
	"crypto/tls"
	"io"
	"net"

	"github.com/pingcap/TiProxy/lib/util/errors"
	"github.com/pingcap/TiProxy/pkg/manager/namespace"
	"github.com/pingcap/TiProxy/pkg/proxy/backend"
	pnet "github.com/pingcap/TiProxy/pkg/proxy/net"
	"github.com/pingcap/tidb/parser/mysql"
	"go.uber.org/zap"
)

var (
	ErrClientConn = errors.New("this is an error from client")
)

type ClientConnection struct {
	logger            *zap.Logger
	frontendTLSConfig *tls.Config    // the TLS config to connect to clients.
	backendTLSConfig  *tls.Config    // the TLS config to connect to TiDB server.
	pkt               *pnet.PacketIO // a helper to read and write data in packet format.
	nsmgr             *namespace.NamespaceManager
	ns                *namespace.Namespace
	connMgr           *backend.BackendConnManager
	proxyProtocol     bool
}

func NewClientConnection(logger *zap.Logger, conn net.Conn, frontendTLSConfig *tls.Config, backendTLSConfig *tls.Config, nsmgr *namespace.NamespaceManager, bemgr *backend.BackendConnManager, proxyProtocol bool) *ClientConnection {
	opts := make([]pnet.PacketIOption, 0, 2)
	if proxyProtocol {
		opts = append(opts, pnet.WithProxy, pnet.WithClient)
	}
	pkt := pnet.NewPacketIO(conn, opts...)
	return &ClientConnection{
		logger:            logger.With(zap.Bool("proxy-protocol", proxyProtocol)),
		frontendTLSConfig: frontendTLSConfig,
		backendTLSConfig:  backendTLSConfig,
		pkt:               pkt,
		nsmgr:             nsmgr,
		connMgr:           bemgr,
		proxyProtocol:     proxyProtocol,
	}
}

func (cc *ClientConnection) connectBackend(ctx context.Context) error {
	ns, ok := cc.nsmgr.GetNamespace("default")
	if !ok {
		return errors.New("failed to find a namespace")
	}
	cc.ns = ns
	router := ns.GetRouter()
	addr, err := router.Route(cc.connMgr)
	if err != nil {
		return err
	}
	if err = cc.connMgr.Connect(ctx, addr, cc.pkt, cc.frontendTLSConfig, cc.backendTLSConfig, cc.proxyProtocol); err != nil {
		return err
	}
	return nil
}

func (cc *ClientConnection) Run(ctx context.Context) {
	if err := cc.connectBackend(ctx); err != nil {
		cc.logger.Info("new connection fails", zap.Error(err))
		return
	}

	if err := cc.processMsg(ctx); err != nil {
		clientErr := errors.Is(err, ErrClientConn)
		if !(clientErr && errors.Is(err, io.EOF)) {
			cc.logger.Info("process message fails", zap.Error(err), zap.Bool("clientErr", clientErr), zap.Bool("serverErr", !clientErr))
		}
	}
}

func (cc *ClientConnection) processMsg(ctx context.Context) error {
	for {
		cc.pkt.ResetSequence()
		clientPkt, err := cc.pkt.ReadPacket()
		if err != nil {
			return err
		}
		err = cc.connMgr.ExecuteCmd(ctx, clientPkt, cc.pkt)
		if err != nil {
			return err
		}
		cmd := clientPkt[0]
		switch cmd {
		case mysql.ComQuit:
			return nil
		}
	}
}

func (cc *ClientConnection) Close() error {
	return errors.Collect(ErrCloseConn, cc.pkt.Close(), cc.connMgr.Close())
}
