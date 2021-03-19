// Copyright (c) 2020 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package controlclient

import "errors"

var (
	errNoCertStore              = errors.New("no certificate store")
	errCertificateNotConfigured = errors.New("no certificate subject configured")
)
