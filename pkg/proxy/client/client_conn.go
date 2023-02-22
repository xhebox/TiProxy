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
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/pingcap/TiProxy/lib/util/errors"
	"github.com/pingcap/TiProxy/lib/util/waitgroup"
	pnet "github.com/pingcap/TiProxy/pkg/proxy/net"
	"github.com/pingcap/tidb/parser/mysql"
	"go.uber.org/zap"
)

var (
	ErrClientConn = errors.New("this is an error from client")
)

// ClientConnection migrates a session from one BackendConnection to another.
//
// The signal processing goroutine tries to migrate the session once it receives a signal.
// If the session is not ready at that time, the cmd executing goroutine will try after executing commands.
//
// If redirection fails, it doesn't retry and waits for the next signal, because:
// - If it disconnects immediately: it's even worse than graceful shutdown.
// - If it retries after each command: the latency will be unacceptable afterwards if it always fails.
// - If it stops receiving signals: the previous new backend may be abnormal but the next new backend may be good.
type ClientConnection struct {
	// processLock makes redirecting and command processing exclusive.
	processLock       sync.Mutex
	wg                waitgroup.WaitGroup
	logger            *zap.Logger
	frontendTLSConfig *tls.Config // the TLS config to connect to clients.
	backendTLSConfig  *tls.Config // the TLS config to connect to TiDB server.
	// signalReceived is used to notify the signal processing goroutine.
	signalReceived chan signalType
	authenticator  *Authenticator
	cmdProcessor   *CmdProcessor
	eventReceiver  unsafe.Pointer
	config         *BCConfig
	// type *signalRedirect, it saves the last signal if there are multiple signals.
	// It will be set to nil after migration.
	signal unsafe.Pointer
	// redirectResCh is used to notify the event receiver asynchronously.
	redirectResCh      chan *redirectResult
	closeStatus        atomic.Int32
	checkBackendTicker *time.Ticker
	// cancelFunc is used to cancel the signal processing goroutine.
	cancelFunc       context.CancelFunc
	clientIO         *pnet.PacketIO
	backendIO        *pnet.PacketIO
	handshakeHandler HandshakeHandler
	ctxmap           sync.Map
	connectionID     uint64
}

func NewClientConnection(logger *zap.Logger, frontendTLSConfig *tls.Config, backendTLSConfig *tls.Config,
	hsHandler HandshakeHandler, connID uint64, bcfg *BCConfig) *ClientConnection {
	bcfg.check()
	return &ClientConnection{
		logger:            logger.With(zap.Bool("proxy-protocol", bcfg.ProxyProtocol)),
		frontendTLSConfig: frontendTLSConfig,
		backendTLSConfig:  backendTLSConfig,
		config:            bcfg,
		connectionID:      connID,
		cmdProcessor:      NewCmdProcessor(),
		handshakeHandler:  hsHandler,
		authenticator: &Authenticator{
			proxyProtocol:     bcfg.ProxyProtocol,
			requireBackendTLS: bcfg.RequireBackendTLS,
			salt:              GenerateSalt(20),
		},
		// There are 2 types of signals, which may be sent concurrently.
		signalReceived: make(chan signalType, signalTypeNums),
		redirectResCh:  make(chan *redirectResult, 1),
	}
}

// ConnectionID implements RedirectableConn.ConnectionID interface.
// It returns the ID of the frontend connection. The ID stays still after session migration.
func (mgr *ClientConnection) ConnectionID() uint64 {
	return mgr.connectionID
}

func (cc *ClientConnection) Run(ctx context.Context, conn net.Conn) {
	var err error
	var msg string

	opts := make([]pnet.PacketIOption, 0, 2)
	opts = append(opts, pnet.WithWrapError(ErrClientConn))
	if cc.config.ProxyProtocol {
		opts = append(opts, pnet.WithProxy)
	}
	clientIO := pnet.NewPacketIO(conn, opts...)

	if err = cc.Connect(ctx, clientIO); err != nil {
		msg = "new connection failed"
		goto clean
	}
	if err = cc.processMsg(ctx); err != nil {
		msg = "fails to relay the connection"
		goto clean
	}

clean:
	clientErr := errors.Is(err, ErrClientConn)
	// EOF: client closes; DeadlineExceeded: graceful shutdown; Closed: shut down.
	if clientErr && (errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, net.ErrClosed)) {
		return
	}
	cc.logger.Info(msg, zap.Error(err), zap.Bool("clientErr", clientErr), zap.Bool("serverErr", !clientErr))
}

func (cc *ClientConnection) processMsg(ctx context.Context) error {
	for {
		cc.clientIO.ResetSequence()
		clientPkt, err := cc.clientIO.ReadPacket()
		if err != nil {
			return err
		}
		err = cc.ExecuteCmd(ctx, clientPkt)
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

// Close releases all resources.
func (cc *ClientConnection) Close() error {
	cc.closeStatus.Store(statusClosing)
	if cc.checkBackendTicker != nil {
		cc.checkBackendTicker.Stop()
	}
	if cc.cancelFunc != nil {
		cc.cancelFunc()
		cc.cancelFunc = nil
	}
	cc.wg.Wait()

	var connErr error
	var addr string
	cc.processLock.Lock()
	if cc.backendIO != nil {
		addr = cc.ServerAddr()
		connErr = cc.backendIO.Close()
		cc.backendIO = nil
	}
	cc.processLock.Unlock()

	handErr := cc.handshakeHandler.OnConnClose(cc)

	eventReceiver := cc.getEventReceiver()
	if eventReceiver != nil {
		// Notify the receiver if there's any event.
		if len(cc.redirectResCh) > 0 {
			cc.notifyRedirectResult(context.Background(), <-cc.redirectResCh)
		}
		// Just notify it with the current address.
		if len(addr) > 0 {
			if err := eventReceiver.OnConnClosed(addr, cc); err != nil {
				cc.logger.Error("close connection error", zap.String("addr", addr), zap.NamedError("notify_err", err))
			}
		}
	}
	cc.closeStatus.Store(statusClosed)
	return errors.Collect(ErrCloseConnMgr, connErr, handErr, cc.clientIO.Close())
}
