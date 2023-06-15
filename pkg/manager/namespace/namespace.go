// Copyright 2023 PingCAP, Inc.
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 Ipalfish, Inc.
// SPDX-License-Identifier: Apache-2.0

package namespace

import (
	"github.com/pingcap/TiProxy/pkg/manager/infosync"
	"github.com/pingcap/TiProxy/pkg/manager/router"
)

type Namespace struct {
	name   string
	user   string
	router router.Router
	is     *infosync.InfoSyncer
}

func (n *Namespace) Name() string {
	return n.name
}

func (n *Namespace) User() string {
	return n.user
}

func (n *Namespace) GetRouter() router.Router {
	return n.router
}

func (n *Namespace) Close() {
	if n.router != nil {
		n.router.Close()
	}
	if n.is != nil {
		n.is.Close()
	}
}
