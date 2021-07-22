// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import "errors"

// ErrConfigurationInvalidLength happens when deserializing a configuration of invalid length.
var ErrConfigurationInvalidLength = errors.New("invalid encoded configuration length")
