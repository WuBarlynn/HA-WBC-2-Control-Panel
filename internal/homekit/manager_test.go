package homekit

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/brutella/hap/characteristic"
	"github.com/brutella/hap/service"

	"ha-wbc-console/internal/store"
)

func TestNewPersistsStablePairingConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.json")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := New(st, "test")
	if err != nil {
		t.Fatal(err)
	}
	firstStatus := first.Status()
	if !regexp.MustCompile(`^\d{3}-\d{2}-\d{3}$`).MatchString(firstStatus.Pin) {
		t.Fatalf("unexpected formatted PIN %q", firstStatus.Pin)
	}
	if firstStatus.SetupURI == "" {
		t.Fatal("expected setup URI")
	}

	reopened, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(reopened, "test")
	if err != nil {
		t.Fatal(err)
	}
	secondStatus := second.Status()
	if firstStatus.Pin != secondStatus.Pin || firstStatus.SetupURI != secondStatus.SetupURI {
		t.Fatalf("pairing identity changed: first=%+v second=%+v", firstStatus, secondStatus)
	}
}

func TestSetupURI(t *testing.T) {
	got := setupURI("123-45-678", "ABCD")
	const want = "X-HM://0023OA632ABCD"
	if got != want {
		t.Fatalf("setupURI() = %q, want %q", got, want)
	}
}

func TestResetPairingsKeepsBridgeIdentity(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	hapStore := st.HomeKitStore()
	if err := hapStore.Set("uuid", []byte("bridge-id")); err != nil {
		t.Fatal(err)
	}
	if err := hapStore.Set("controller.pairing", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if st.HomeKitPairingCount() != 1 {
		t.Fatalf("pairing count = %d, want 1", st.HomeKitPairingCount())
	}
	if err := st.ClearHomeKitPairings(); err != nil {
		t.Fatal(err)
	}
	if st.HomeKitPairingCount() != 0 {
		t.Fatalf("pairing count = %d, want 0", st.HomeKitPairingCount())
	}
	if got, err := hapStore.Get("uuid"); err != nil || string(got) != "bridge-id" {
		t.Fatalf("bridge identity lost: value=%q err=%v", got, err)
	}
	if _, err := hapStore.Get("controller.pairing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pairing still exists: %v", err)
	}
}

func TestAccessoryIDIsStableAndHomeKitSafe(t *testing.T) {
	for _, id := range []string{"0000000000000000", "1234567890abcdef", "ffffffffffffffff", "legacy-device-id"} {
		first := accessoryID(id)
		second := accessoryID(id)
		if first != second {
			t.Fatalf("accessoryID(%q) is not stable: %d != %d", id, first, second)
		}
		if first < 2 || first > 1<<31-1 {
			t.Fatalf("accessoryID(%q) = %d, want 2..%d", id, first, 1<<31-1)
		}
	}
}

func TestHomeKitServiceName(t *testing.T) {
	for input, want := range map[string]string{
		"HA-WBC-2 控制台": "HA-WBC-2",
		"家庭 控制台":       "HA-WBC-2_Bridge",
		"":             "HA-WBC-2_Bridge",
	} {
		if got := homeKitServiceName(input); got != want {
			t.Errorf("homeKitServiceName(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestHomeKitInterfaces(t *testing.T) {
	ifaces, err := homeKitInterfaces(nil, nil)
	if err != nil {
		t.Skipf("no suitable LAN interface in test environment: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0] == "" {
		t.Fatalf("homeKitInterfaces() = %v, want exactly one interface", ifaces)
	}
}

func TestSelectHomeKitInterface(t *testing.T) {
	_, wan, _ := net.ParseCIDR("10.0.0.1/24")
	_, lan, _ := net.ParseCIDR("192.168.123.1/24")
	candidates := []homeKitInterface{{name: "wan", network: wan}, {name: "br-lan", network: lan}}

	if got := selectHomeKitInterface(candidates, nil, net.ParseIP("192.168.123.2")); got != "br-lan" {
		t.Fatalf("request subnet selected %q, want br-lan", got)
	}
	devices := []store.Device{{Addr: "192.168.123.50:80"}}
	if got := selectHomeKitInterface(candidates, devices, nil); got != "br-lan" {
		t.Fatalf("device subnet selected %q, want br-lan", got)
	}
}

func TestAddServiceName(t *testing.T) {
	s := service.NewSwitch()
	addServiceName(s.S, "主机 电源")

	values := map[string]string{}
	for _, c := range s.Cs {
		if c.Type == characteristic.TypeName || c.Type == characteristic.TypeConfiguredName {
			values[c.Type] = c.Value().(string)
		}
	}
	if values[characteristic.TypeName] != "主机 电源" || values[characteristic.TypeConfiguredName] != "主机 电源" {
		t.Fatalf("service names = %#v", values)
	}
}

func TestValidatePin(t *testing.T) {
	for _, pin := range []string{"", "1234567", "abcdefgh", "12345678", "00000000"} {
		if err := validatePin(pin); err == nil {
			t.Errorf("validatePin(%q) unexpectedly succeeded", pin)
		}
	}
	if err := validatePin("28467193"); err != nil {
		t.Fatalf("valid PIN rejected: %v", err)
	}
}
