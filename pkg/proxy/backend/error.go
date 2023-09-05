// Copyright 2023 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"github.com/pingcap/tiproxy/lib/util/errors"
)

const (
	connectErrMsg         = "No available TiDB instances, please check TiDB cluster"
	parsePktErrMsg        = "TiProxy fails to parse the packet, please contact PingCAP"
	handshakeErrMsg       = "TiProxy fails to connect to TiDB, please check network"
	capabilityErrMsg      = "Verify TiDB capability failed, please upgrade TiDB"
	requireProxyTLSErrMsg = "Require TLS config on TiProxy when require-backend-tls=true"
	requireTiDBTLSErrMsg  = "Require TLS config on TiDB when require-backend-tls=true"
)

var (
	ErrClientConn  = errors.New("this is an error from client")
	ErrBackendConn = errors.New("this is an error from backend")
)
