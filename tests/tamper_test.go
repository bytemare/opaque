// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

// todo: create opaque_bench.go and move benchmarks there

// todo: move all the tampering tests to this file
// todo: list the types of attacks covered
// todo: identify missing types of attacks
// todo: test attack using different contexts for client and server
// todo: replaying KE1/KE3 messages or reusing client/server state, which could allow session hijacking or key reuse attacks.
// todo: Identity binding and session binding – Tests focus on malformed keys and MACs but do not cover tampering with ClientIdentity, ServerIdentity, or nonces, leaving potential gaps in checking that identities are properly bound to the session.
// todo: unknown key share attack, à la Kaliski
