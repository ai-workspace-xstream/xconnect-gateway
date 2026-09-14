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

func TestWireGuardRouteCIDRsExtractsPeerRoutes(t *testing.T) {
	routes := wireGuardRouteCIDRs(`peer-a 10.77.0.9/32 10.77.0.10/32
peer-b 2001:db8::9/128
peer-c 0.0.0.0/0 ::/0`)
	want := []string{"10.77.0.9/32", "10.77.0.10/32", "2001:db8::9/128"}
	if len(routes) != len(want) {
		t.Fatalf("routes = %#v, want %#v", routes, want)
	}
	for i := range want {
		if routes[i] != want[i] {
			t.Fatalf("routes = %#v, want %#v", routes, want)
		}
	}
}
