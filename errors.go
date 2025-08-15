// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

/*
TODO:
	- verify all errors have been tested against: maybe add a lint or check?
	- verify that test verify full error chains
	- provide examples for error codes to test against for users:
	    - if Err1, do this
		- if Err2, do that
*/

var (
	// ErrConfiguration indicates that the configuration is invalid.
	ErrConfiguration = ErrCodeConfiguration.New("")

	// ErrRegistration indicates that the registration process failed.
	ErrRegistration = ErrCodeRegistration.New("")

	// ErrAuthentication indicates that the authentication process failed.
	ErrAuthentication = ErrCodeAuthentication.New("")

	// ErrRegistrationRequest indicates an error with a registration request.
	ErrRegistrationRequest = ErrCodeMessage.New("invalid registration request")

	// ErrRegistrationResponse indicates an error with a registration response.
	ErrRegistrationResponse = ErrCodeMessage.New("invalid registration response")

	// ErrRegistrationRecord indicates an error with a registration record.
	ErrRegistrationRecord = ErrCodeMessage.New("invalid registration record")

	// ErrKE1 indicates an error with a KE1 message.
	ErrKE1 = ErrCodeMessage.New("invalid KE1 message")

	// ErrKE2 indicates an error with a KE2 message.
	ErrKE2 = ErrCodeMessage.New("invalid KE2 message")

	// ErrKE3 indicates an error with a KE3 message.
	ErrKE3 = ErrCodeMessage.New("invalid KE3 message")

	// ErrServerKeyMaterial indicates that the server's key material is invalid.
	ErrServerKeyMaterial = ErrCodeServerKeyMaterial.New("")

	// ErrServerOptions indicates that the provided server options are invalid.
	ErrServerOptions = ErrCodeServerOptions.New("")

	// ErrClientRecord indicates that the client record is invalid.
	ErrClientRecord = ErrCodeClientRecord.New("")

	// ErrClientState indicates that the client state is invalid.
	ErrClientState = ErrCodeClientState.New("")

	// ErrClientOptions indicates that the client options are invalid.
	ErrClientOptions = ErrCodeClientOptions.New("")

	// todo: use this if tampering has been detected?
	ErrCriticalAbort = errors.New("critical - abort protocol")
)

// ErrorCode represents the type of error in the OPAQUE protocol. It is used to categorize errors and provide
// a consistent way to handle error conditions.
type ErrorCode byte

const (
	ErrCodeUnknown ErrorCode = iota
	ErrCodeConfiguration
	ErrCodeRegistration
	ErrCodeAuthentication
	ErrCodeMessage
	ErrCodeServerKeyMaterial
	ErrCodeServerOptions
	ErrCodeClientRecord
	ErrCodeClientState
	ErrCodeClientOptions
)

// New creates a new Error with the given message and errors.
func (c ErrorCode) New(message string, errs ...error) *Error {
	if message == "" {
		message = strings.Replace(c.String(), "_", " ", -1)
	}

	return &Error{
		Code:    c,
		Message: message,
		Err:     errors.Join(errs...),
	}
}

var codeNames = map[ErrorCode]string{
	ErrCodeUnknown:           "unknown_error",
	ErrCodeConfiguration:     "configuration_error",
	ErrCodeRegistration:      "registration_error",
	ErrCodeAuthentication:    "authentication_error",
	ErrCodeMessage:           "message_error",
	ErrCodeServerKeyMaterial: "server_key_material_error",
	ErrCodeServerOptions:     "server_options_error",
	ErrCodeClientRecord:      "client_record_error",
	ErrCodeClientState:       "client_state_error",
	ErrCodeClientOptions:     "client_options_error",
}

// String returns the string representation of the ErrorCode. If the code is not recognized, it returns "unknown_error".
func (c ErrorCode) String() string {
	if name, ok := codeNames[c]; ok {
		return name
	}

	return codeNames[ErrCodeUnknown]
}

// Error implements the error interface for the ErrorCode type. It returns a string representation of the error code.
func (c ErrorCode) Error() string {
	return c.String()
}

// Error represents an error in the OPAQUE protocol.
type Error struct {
	Err     error
	Message string
	Code    ErrorCode
}

// Error implements the error interface for the Error type. By convention, we return only the concise form of the
// current error, without the cause. The cause can be retrieved with the Unwrap() method.
func (e *Error) Error() string { return e.Message }

// Unwrap implements the errors.Unwrap method for the Error type. It allows retrieving the underlying error, if any.
func (e *Error) Unwrap() error { return e.Err }

// Join wraps the provided error to the current error.
func (e *Error) Join(errs ...error) error {
	return errors.Join(e, errors.Join(errs...))
}

// LogValue implements the slog.LogValuer interface for the Error type.
func (e *Error) LogValue() slog.Value {
	attrs := []slog.Attr{
		slog.Int("code", int(e.Code)),
		slog.String("code_name", e.Code.String()),
		slog.String("message", e.Message),
	}

	if e.Err != nil {
		attrs = append(attrs, slog.Any("error", e.Err))
	}

	return slog.GroupValue(attrs...)
}

func printV(f fmt.State, err error, depth int) {
	if err == nil {
		return
	}

	prefix := strings.Repeat("  ", depth)
	_, _ = fmt.Fprintf(f, "\n%s↳ %v", prefix, err)

	switch u := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range u.Unwrap() {
			printV(f, child, depth+1)
		}
	case interface{ Unwrap() error }:
		printV(f, u.Unwrap(), depth+1)
	default:
		// no-op: unknown error type; nothing to unwrap
	}
}

func (e *Error) formatV(f fmt.State) {
	// header with code
	_, _ = fmt.Fprintf(f, "code=%d(%s)", e.Code, e.Code.String())
	if e.Message != "" {
		_, _ = fmt.Fprintf(f, " message=%q", e.Message)
	}

	// unwrap error chain
	if e.Err != nil {
		printV(f, e.Err, 0)
	}
}

// Format implements the fmt.Formatter interface for the Error type. It allows formatting the error in different ways.
func (e *Error) Format(f fmt.State, verb rune) {
	switch verb {
	case 'v':
		if f.Flag('+') {
			e.formatV(f)
			return
		}
		fallthrough
	case 's':
		_, _ = io.WriteString(f, e.Error()) // human-readable
	case 'q':
		_, _ = fmt.Fprintf(f, "%q", e.Error()) // quoted string
	default:
		_, _ = io.WriteString(f, e.Error()) // safe default
	}
}

// Is implements the errors.Is method for the Error type. It allows checking if the error is of a specific ErrorCode.
func (e *Error) Is(target error) bool {
	// todo: test this case
	switch t := target.(type) {
	case ErrorCode: // errors.Is(err, ErrCodeAuthentication)
		return e.Code == t
	case *Error: // errors.Is(err, &Error{Code: ErrCodeAuthentication})
		return e.Code == t.Code
	default:
		return false
	}
}
