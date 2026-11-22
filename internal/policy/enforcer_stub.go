//go:build !linux

package policy

import (
	"context"
	"errors"
)

var errUnsupportedPlatform = errors.New("gateway policy enforcer is only supported on Linux")

// Apply is only supported on Linux gateway hosts.
func Apply(context.Context, CompiledRuleset) error {
	return errUnsupportedPlatform
}

// Teardown is only supported on Linux gateway hosts.
func Teardown(context.Context, string) error {
	return errUnsupportedPlatform
}
