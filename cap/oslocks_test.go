package cap

import (
	"syscall"
	"testing"
)

func TestValidatePAMergesLauncherChroot(t *testing.T) {
	pa := &syscall.ProcAttr{
		Sys: &syscall.SysProcAttr{Setpgid: true},
	}

	needChroot, err := validatePA(pa, "/configured-jail")
	if err != nil {
		t.Fatalf("validatePA failed: %v", err)
	}
	if !needChroot {
		t.Fatal("validatePA silently dropped the configured chroot")
	}
	if got := pa.Sys.Chroot; got != "/configured-jail" {
		t.Fatalf("Chroot=%q, want %q", got, "/configured-jail")
	}
	if !pa.Sys.Setpgid {
		t.Fatal("validatePA discarded the callback's SysProcAttr fields")
	}
}

func TestValidatePADoesNotMutateChrootOnError(t *testing.T) {
	tests := []struct {
		name       string
		sys        *syscall.SysProcAttr
		wantErr    error
		wantChroot string
	}{
		{
			name:    "credential",
			sys:     &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1}},
			wantErr: ErrAmbiguousIDs,
		},
		{
			name:    "ambient",
			sys:     &syscall.SysProcAttr{AmbientCaps: []uintptr{1}},
			wantErr: ErrAmbiguousAmbient,
		},
		{
			name: "credential before ambient",
			sys: &syscall.SysProcAttr{
				Credential:  &syscall.Credential{Uid: 1},
				AmbientCaps: []uintptr{1},
			},
			wantErr: ErrAmbiguousIDs,
		},
		{
			name: "callback chroot before credential",
			sys: &syscall.SysProcAttr{
				Chroot:     "/callback-jail",
				Credential: &syscall.Credential{Uid: 1},
			},
			wantErr:    ErrAmbiguousChroot,
			wantChroot: "/callback-jail",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sys := test.sys
			pa := &syscall.ProcAttr{Sys: sys}

			needChroot, err := validatePA(pa, "/configured-jail")
			if err != test.wantErr {
				t.Fatalf("validatePA error=%v, want %v", err, test.wantErr)
			}
			if needChroot {
				t.Fatal("validatePA reported a usable chroot on error")
			}
			if pa.Sys != sys {
				t.Fatal("validatePA replaced the callback's SysProcAttr on error")
			}
			if got := sys.Chroot; got != test.wantChroot {
				t.Fatalf("Chroot=%q after error, want %q", got, test.wantChroot)
			}
		})
	}
}
