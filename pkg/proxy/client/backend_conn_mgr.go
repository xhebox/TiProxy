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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cenkalti/backoff/v4"
	gomysql "github.com/go-mysql-org/go-mysql/mysql"
	"github.com/pingcap/TiProxy/lib/util/errors"
	"github.com/pingcap/TiProxy/pkg/manager/router"
	pnet "github.com/pingcap/TiProxy/pkg/proxy/net"
	"github.com/pingcap/tidb/parser/mysql"
	"github.com/siddontang/go/hack"
	"go.uber.org/zap"
)

var (
	ErrCloseConnMgr = errors.New("failed to close connection manager")
)

const (
	DialTimeout          = 1 * time.Second
	CheckBackendInterval = time.Minute
)

const (
	sqlQueryState    = "SHOW SESSION_STATES"
	sqlSetState      = "SET SESSION_STATES '%s'"
	sessionStatesCol = "Session_states"
	sessionTokenCol  = "Session_token"
	currentDBKey     = "current-db"
)

type signalType int

const (
	signalTypeRedirect signalType = iota
	signalTypeGracefulClose
	signalTypeNums
)

type signalRedirect struct {
	newAddr string
}

type redirectResult struct {
	err  error
	from string
	to   string
}

const (
	statusActive      int32 = iota
	statusNotifyClose       // notified to graceful close
	statusClosing           // really closing
	statusClosed
)

type BCConfig struct {
	ProxyProtocol        bool
	RequireBackendTLS    bool
	CheckBackendInterval time.Duration
}

func (cfg *BCConfig) check() {
	if cfg.CheckBackendInterval == time.Duration(0) {
		cfg.CheckBackendInterval = CheckBackendInterval
	}
}

// Connect connects to the first backend and then start watching redirection signals.
func (cc *ClientConnection) Connect(ctx context.Context, clientIO *pnet.PacketIO) error {
	cc.processLock.Lock()
	defer cc.processLock.Unlock()

	err := cc.authenticator.handshakeFirstTime(cc.logger.Named("authenticator"), cc, clientIO, cc.handshakeHandler, cc.getBackendIO, cc.frontendTLSConfig, cc.backendTLSConfig)
	cc.handshakeHandler.OnHandshake(cc, cc.ServerAddr(), err)
	if err != nil {
		WriteUserError(cc.clientIO, err, cc.logger)
		return err
	}

	cc.cmdProcessor.capability = cc.authenticator.capability
	childCtx, cancelFunc := context.WithCancel(ctx)
	cc.cancelFunc = cancelFunc
	cc.resetCheckBackendTicker()
	cc.wg.Run(func() {
		cc.processSignals(childCtx)
	})
	return nil
}

func (cc *ClientConnection) getBackendIO(cctx ConnContext, auth *Authenticator, resp *pnet.HandshakeResp, timeout time.Duration) (*pnet.PacketIO, error) {
	r, err := cc.handshakeHandler.GetRouter(cctx, resp)
	if err != nil {
		return nil, WrapUserError(err, err.Error())
	}
	// Reasons to wait:
	// - The TiDB instances may not be initialized yet
	// - One TiDB may be just shut down and another is just started but not ready yet
	bctx, cancel := context.WithTimeout(context.Background(), timeout)
	selector := r.GetBackendSelector()
	startTime := time.Now()
	var addr string
	var origErr error
	io, err := backoff.RetryNotifyWithData(
		func() (*pnet.PacketIO, error) {
			// Try to connect to all backup backends one by one.
			addr, err = selector.Next()
			// If all addrs are enumerated, reset and try again.
			if err == nil && addr == "" {
				selector.Reset()
				addr, err = selector.Next()
			}
			if err != nil {
				return nil, backoff.Permanent(WrapUserError(err, err.Error()))
			}
			if addr == "" {
				return nil, router.ErrNoInstanceToSelect
			}

			var cn net.Conn
			cn, err = net.DialTimeout("tcp", addr, DialTimeout)
			if err != nil {
				return nil, errors.Wrapf(err, "dial backend %s error", addr)
			}

			if err = selector.Succeed(cc); err != nil {
				// Bad luck: the backend has been recycled or shut down just after the selector returns it.
				if ignoredErr := cn.Close(); ignoredErr != nil {
					cc.logger.Error("close backend connection failed", zap.String("addr", addr), zap.Error(ignoredErr))
				}
				return nil, err
			}

			cc.logger.Info("connected to backend", zap.String("addr", addr))
			// NOTE: should use DNS name as much as possible
			// Usually certs are signed with domain instead of IP addrs
			// And `RemoteAddr()` will return IP addr
			cc.backendIO = pnet.NewPacketIO(cn, pnet.WithRemoteAddr(addr, cn.RemoteAddr()))
			return cc.backendIO, nil
		},
		backoff.WithContext(backoff.NewConstantBackOff(200*time.Millisecond), bctx),
		func(err error, d time.Duration) {
			origErr = err
			cc.handshakeHandler.OnHandshake(cctx, addr, err)
		},
	)
	cancel()

	duration := time.Since(startTime)
	addGetBackendMetrics(duration)
	if err != nil {
		cc.logger.Error("get backend failed", zap.Duration("duration", duration), zap.NamedError("last_err", origErr))
	} else if duration >= 3*time.Second {
		cc.logger.Warn("get backend slow", zap.Duration("duration", duration), zap.NamedError("last_err", origErr),
			zap.Stringer("backend_addr", cc.backendIO.RemoteAddr()))
	}
	if err != nil && errors.Is(err, context.DeadlineExceeded) {
		if origErr != nil {
			err = origErr
		}
	}
	return io, err
}

// ExecuteCmd forwards messages between the client and the backend.
// If it finds that the session is ready for redirection, it migrates the session.
func (cc *ClientConnection) ExecuteCmd(ctx context.Context, request []byte) error {
	if len(request) < 1 {
		return mysql.ErrMalformPacket
	}
	cmd := request[0]
	startTime := time.Now()
	cc.processLock.Lock()
	defer cc.processLock.Unlock()

	switch cc.closeStatus.Load() {
	case statusClosing, statusClosed:
		return nil
	}
	defer cc.resetCheckBackendTicker()
	waitingRedirect := atomic.LoadPointer(&cc.signal) != nil
	holdRequest, err := cc.cmdProcessor.executeCmd(request, cc.clientIO, cc.backendIO, waitingRedirect)
	if !holdRequest {
		addCmdMetrics(cmd, cc.ServerAddr(), startTime)
	}
	if err != nil {
		if !IsMySQLError(err) {
			return err
		} else {
			cc.logger.Debug("got a mysql error", zap.Error(err))
		}
	}
	if err == nil {
		switch cmd {
		case mysql.ComQuit:
			return nil
		case mysql.ComSetOption:
			val := binary.LittleEndian.Uint16(request[1:])
			switch val {
			case 0:
				cc.authenticator.capability |= mysql.ClientMultiStatements
				cc.cmdProcessor.capability |= mysql.ClientMultiStatements
			case 1:
				cc.authenticator.capability &^= mysql.ClientMultiStatements
				cc.cmdProcessor.capability &^= mysql.ClientMultiStatements
			default:
				return errors.Errorf("unrecognized set_option value:%d", val)
			}
		case mysql.ComChangeUser:
			username, db := pnet.ParseChangeUser(request)
			cc.authenticator.changeUser(username, db)
			return nil
		}
	}
	// Even if it meets an MySQL error, it may have changed the status, such as when executing multi-statements.
	if cc.cmdProcessor.finishedTxn() {
		if waitingRedirect && holdRequest {
			cc.tryRedirect(ctx)
			// Execute the held request no matter redirection succeeds or not.
			_, err = cc.cmdProcessor.executeCmd(request, cc.clientIO, cc.backendIO, false)
			addCmdMetrics(cmd, cc.ServerAddr(), startTime)
			if err != nil && !IsMySQLError(err) {
				return err
			}
		} else if cc.closeStatus.Load() == statusNotifyClose {
			cc.tryGracefulClose(ctx)
		} else if waitingRedirect {
			cc.tryRedirect(ctx)
		}
	}
	// Ignore MySQL errors, only return unexpected errors.
	return nil
}

// SetEventReceiver implements RedirectableConn.SetEventReceiver interface.
// The receiver sends redirection signals and watches redirecting events.
func (cc *ClientConnection) SetEventReceiver(receiver router.ConnEventReceiver) {
	atomic.StorePointer(&cc.eventReceiver, unsafe.Pointer(&receiver))
}

func (cc *ClientConnection) getEventReceiver() router.ConnEventReceiver {
	eventReceiver := (*router.ConnEventReceiver)(atomic.LoadPointer(&cc.eventReceiver))
	if eventReceiver == nil {
		return nil
	}
	return *eventReceiver
}

func (cc *ClientConnection) initSessionStates(backendIO *pnet.PacketIO, sessionStates string) error {
	// Do not lock here because the caller already locks.
	sessionStates = strings.ReplaceAll(sessionStates, "\\", "\\\\")
	sessionStates = strings.ReplaceAll(sessionStates, "'", "\\'")
	sql := fmt.Sprintf(sqlSetState, sessionStates)
	_, _, err := cc.cmdProcessor.query(backendIO, sql)
	return err
}

func (cc *ClientConnection) querySessionStates() (sessionStates, sessionToken string, err error) {
	// Do not lock here because the caller already locks.
	var result *gomysql.Result
	if result, _, err = cc.cmdProcessor.query(cc.backendIO, sqlQueryState); err != nil {
		return
	}
	if sessionStates, err = result.GetStringByName(0, sessionStatesCol); err != nil {
		return
	}
	sessionToken, err = result.GetStringByName(0, sessionTokenCol)
	return
}

// processSignals runs in a goroutine to:
// - Receive redirection signals and then try to migrate the session.
// - Send redirection results to the event receiver.
// - Check if the backend is still alive.
func (cc *ClientConnection) processSignals(ctx context.Context) {
	for {
		select {
		case s := <-cc.signalReceived:
			// Redirect the session immediately just in case the session is finishedTxn.
			cc.processLock.Lock()
			switch s {
			case signalTypeGracefulClose:
				cc.tryGracefulClose(ctx)
			case signalTypeRedirect:
				cc.tryRedirect(ctx)
			}
			cc.processLock.Unlock()
		case rs := <-cc.redirectResCh:
			cc.notifyRedirectResult(ctx, rs)
		case <-cc.checkBackendTicker.C:
			cc.checkBackendActive()
		case <-ctx.Done():
			return
		}
	}
}

// tryRedirect tries to migrate the session if the session is redirect-able.
// NOTE: processLock should be held before calling this function.
func (cc *ClientConnection) tryRedirect(ctx context.Context) {
	switch cc.closeStatus.Load() {
	case statusNotifyClose, statusClosing, statusClosed:
		return
	}
	signal := (*signalRedirect)(atomic.LoadPointer(&cc.signal))
	if signal == nil {
		return
	}
	if !cc.cmdProcessor.finishedTxn() {
		return
	}

	rs := &redirectResult{
		from: cc.ServerAddr(),
		to:   signal.newAddr,
	}
	defer func() {
		// The `mgr` won't be notified again before it calls `OnRedirectSucceed`, so simply `StorePointer` is also fine.
		atomic.CompareAndSwapPointer(&cc.signal, unsafe.Pointer(signal), nil)
		// Notifying may block. Notify the receiver asynchronously to:
		// - Reduce the latency of session migration
		// - Avoid the risk of deadlock
		cc.redirectResCh <- rs
	}()
	var sessionStates, sessionToken string
	if sessionStates, sessionToken, rs.err = cc.querySessionStates(); rs.err != nil {
		return
	}
	if rs.err = cc.updateAuthInfoFromSessionStates(hack.Slice(sessionStates)); rs.err != nil {
		return
	}

	var cn net.Conn
	cn, rs.err = net.DialTimeout("tcp", rs.to, DialTimeout)
	if rs.err != nil {
		cc.handshakeHandler.OnHandshake(cc, rs.to, rs.err)
		return
	}
	newBackendIO := pnet.NewPacketIO(cn, pnet.WithRemoteAddr(rs.to, cn.RemoteAddr()))

	if rs.err = cc.authenticator.handshakeSecondTime(cc.logger, cc.clientIO, newBackendIO, cc.backendTLSConfig, sessionToken); rs.err == nil {
		rs.err = cc.initSessionStates(newBackendIO, sessionStates)
	} else {
		cc.handshakeHandler.OnHandshake(cc, newBackendIO.RemoteAddr().String(), rs.err)
	}
	if rs.err != nil {
		if ignoredErr := newBackendIO.Close(); ignoredErr != nil && !pnet.IsDisconnectError(ignoredErr) {
			cc.logger.Error("close new backend connection failed", zap.Error(ignoredErr))
		}
		return
	}
	if ignoredErr := cc.backendIO.Close(); ignoredErr != nil && !pnet.IsDisconnectError(ignoredErr) {
		cc.logger.Error("close previous backend connection failed", zap.Error(ignoredErr))
	}

	cc.backendIO = newBackendIO
	cc.handshakeHandler.OnHandshake(cc, cc.ServerAddr(), nil)
}

// The original db in the auth info may be dropped during the session, so we need to authenticate with the current db.
// The user may be renamed during the session, but the session cannot detect it, so this will affect the user.
// TODO: this may be a security problem: a different new user may just be renamed to this user name.
func (cc *ClientConnection) updateAuthInfoFromSessionStates(sessionStates []byte) error {
	var statesMap map[string]any
	if err := json.Unmarshal(sessionStates, &statesMap); err != nil {
		return errors.Wrapf(err, "unmarshal session states error")
	}
	// The currentDBKey may be omitted if it's empty. In this case, we still need to update it.
	if currentDB, ok := statesMap[currentDBKey].(string); ok {
		cc.authenticator.updateCurrentDB(currentDB)
	}
	return nil
}

// Redirect implements RedirectableConn.Redirect interface. It redirects the current session to the newAddr.
// Note that the caller requires the function to be non-blocking.
func (cc *ClientConnection) Redirect(newAddr string) {
	// NOTE: ClientConnection may be closing concurrently because of no lock.
	// The eventReceiver may read the new address even after ClientConnection is closed.
	atomic.StorePointer(&cc.signal, unsafe.Pointer(&signalRedirect{
		newAddr: newAddr,
	}))
	switch cc.closeStatus.Load() {
	case statusNotifyClose, statusClosing, statusClosed:
		return
	}
	// Generally, it won't wait because the caller won't send another signal before the previous one finishes.
	cc.signalReceived <- signalTypeRedirect
}

// GetRedirectingAddr implements RedirectableConn.GetRedirectingAddr interface.
// It returns the goal backend address to redirect to.
func (cc *ClientConnection) GetRedirectingAddr() string {
	signal := (*signalRedirect)(atomic.LoadPointer(&cc.signal))
	if signal == nil {
		return ""
	}
	return signal.newAddr
}

func (cc *ClientConnection) notifyRedirectResult(ctx context.Context, rs *redirectResult) {
	if rs == nil {
		return
	}
	eventReceiver := cc.getEventReceiver()
	if eventReceiver == nil {
		return
	}
	if rs.err != nil {
		err := eventReceiver.OnRedirectFail(rs.from, rs.to, cc)
		cc.logger.Warn("redirect connection failed", zap.String("from", rs.from),
			zap.String("to", rs.to), zap.NamedError("redirect_err", rs.err), zap.NamedError("notify_err", err))
	} else {
		err := eventReceiver.OnRedirectSucceed(rs.from, rs.to, cc)
		cc.logger.Info("redirect connection succeeds", zap.String("from", rs.from),
			zap.String("to", rs.to), zap.NamedError("notify_err", err))
	}
}

// GracefulClose waits for the end of the transaction and closes the session.
func (cc *ClientConnection) GracefulClose() {
	cc.closeStatus.Store(statusNotifyClose)
	cc.signalReceived <- signalTypeGracefulClose
}

func (cc *ClientConnection) tryGracefulClose(ctx context.Context) {
	if cc.closeStatus.Load() != statusNotifyClose {
		return
	}
	if !cc.cmdProcessor.finishedTxn() {
		return
	}
	// Closing clientIO will cause the whole connection to be closed.
	if err := cc.clientIO.GracefulClose(); err != nil {
		cc.logger.Warn("graceful close client IO error", zap.Stringer("addr", cc.clientIO.RemoteAddr()), zap.Error(err))
	}
	cc.closeStatus.Store(statusClosing)
}

func (cc *ClientConnection) checkBackendActive() {
	switch cc.closeStatus.Load() {
	case statusClosing, statusClosed:
		return
	}

	cc.processLock.Lock()
	defer cc.processLock.Unlock()
	if !cc.backendIO.IsPeerActive() {
		cc.logger.Info("backend connection is closed, close client connection", zap.Stringer("client", cc.clientIO.RemoteAddr()),
			zap.Stringer("backend", cc.backendIO.RemoteAddr()))
		if err := cc.clientIO.GracefulClose(); err != nil {
			cc.logger.Warn("graceful close client IO error", zap.Stringer("addr", cc.clientIO.RemoteAddr()), zap.Error(err))
		}
		cc.closeStatus.Store(statusClosing)
	}
}

// Checking backend is expensive, so only check it when the client is idle for some time.
// This function should be called within the lock.
func (cc *ClientConnection) resetCheckBackendTicker() {
	if cc.checkBackendTicker == nil {
		cc.checkBackendTicker = time.NewTicker(cc.config.CheckBackendInterval)
	} else {
		cc.checkBackendTicker.Reset(cc.config.CheckBackendInterval)
	}
}

func (cc *ClientConnection) ClientAddr() string {
	if cc.clientIO == nil {
		return ""
	}
	return cc.clientIO.RemoteAddr().String()
}

func (cc *ClientConnection) ServerAddr() string {
	if cc.backendIO == nil {
		return ""
	}
	return cc.backendIO.RemoteAddr().String()
}

func (cc *ClientConnection) ClientInBytes() uint64 {
	if cc.clientIO == nil {
		return 0
	}
	return cc.clientIO.InBytes()
}

func (cc *ClientConnection) ClientOutBytes() uint64 {
	if cc.clientIO == nil {
		return 0
	}
	return cc.clientIO.OutBytes()
}

func (cc *ClientConnection) SetValue(key, val any) {
	cc.ctxmap.Store(key, val)
}

func (cc *ClientConnection) Value(key any) any {
	v, ok := cc.ctxmap.Load(key)
	if !ok {
		return nil
	}
	return v
}
