package iptables

import "testing"

func TestInstall(t *testing.T) {
	a, err := New()
	if err != nil {
		t.Fatal(err)
		t.FailNow()
	}
	_ = a
}

func TestAppend(t *testing.T) {

}
