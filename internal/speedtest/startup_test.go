package speedtest

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStartupCandidatesNormalizeIPv4AndStayWithinProviderRange(t *testing.T) {
	file := filepath.Join(t.TempDir(), "provider.txt")
	if err := os.WriteFile(file, []byte("# official CIDRs\n104.16.0.0/13\n2606:4700::/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ranges, err := readPrefixes(file)
	if err != nil {
		t.Fatal(err)
	}
	got := candidateAddresses([]net.IP{
		net.ParseIP("104.20.8.2"),
		net.ParseIP("104.20.8.2"),
		net.ParseIP("203.0.113.1"),
		net.ParseIP("2606:4700::1"),
	}, ranges, true)
	if want := []string{"104.20.8.2", "2606:4700::1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	if prefixContains(ranges, netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("unrelated address was accepted")
	}
}
