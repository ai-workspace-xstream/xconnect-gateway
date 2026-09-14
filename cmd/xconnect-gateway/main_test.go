package main

import "testing"

func TestInterfaceApplyKeepsExistingWireGuardInterface(t *testing.T) {
	if wireGuardApplyMode(true) != "syncconf" {
		t.Fatal("existing interface must be updated in place")
	}
	if wireGuardApplyMode(false) != "up" {
		t.Fatal("missing interface must use initial wg-quick up")
	}
}
