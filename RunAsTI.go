package RunAsTI

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	seDebugPrivilege = "SeDebugPrivilege"
	tiServiceName    = "TrustedInstaller"
	tiExecutableName = "trustedinstaller.exe"
)

func Run(path string, args []string) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	const (
		seDebugPrivilege = "SeDebugPrivilege"
		tiServiceName    = "TrustedInstaller"
		tiExecutableName = "trustedinstaller.exe"
	)

	checkIfAdmin := func() bool {
		f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			return false
		}
		f.Close()
		return true
	}

	elevate := func() error {
		verb := "runas"
		exe, _ := os.Executable()
		cwd, _ := os.Getwd()
		args := strings.Join(os.Args[1:], " ")

		verbPtr, _ := syscall.UTF16PtrFromString(verb)
		exePtr, _ := syscall.UTF16PtrFromString(exe)
		cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
		argPtr, _ := syscall.UTF16PtrFromString(args)

		var showCmd int32 = 1 //SW_NORMAL

		if err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd); err != nil {
			return err
		}

		os.Exit(0)
		return nil
	}

	enableSeDebugPrivilege := func() error {
		var t windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ALL_ACCESS, &t); err != nil {
			return err
		}

		var luid windows.LUID

		if err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(seDebugPrivilege), &luid); err != nil {
			return fmt.Errorf("LookupPrivilegeValueW failed, error: %v", err)
		}

		ap := windows.Tokenprivileges{
			PrivilegeCount: 1,
		}

		ap.Privileges[0].Luid = luid
		ap.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED

		if err := windows.AdjustTokenPrivileges(t, false, &ap, 0, nil, nil); err != nil {
			return fmt.Errorf("AdjustTokenPrivileges failed, error: %v", err)
		}

		return nil
	}

	parseProcessName := func(exeFile [windows.MAX_PATH]uint16) string {
		for i, v := range exeFile {
			if v <= 0 {
				return string(utf16.Decode(exeFile[:i]))
			}
		}
		return ""
	}

	getTrustedInstallerPid := func() (uint32, error) {

		snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
		if err != nil {
			return 0, err
		}
		defer windows.CloseHandle(snapshot)

		var procEntry windows.ProcessEntry32
		procEntry.Size = uint32(unsafe.Sizeof(procEntry))

		if err := windows.Process32First(snapshot, &procEntry); err != nil {
			return 0, err
		}

		for {
			if strings.EqualFold(parseProcessName(procEntry.ExeFile), tiExecutableName) {
				return procEntry.ProcessID, nil
			} else {
				if err = windows.Process32Next(snapshot, &procEntry); err != nil {
					if err == windows.ERROR_NO_MORE_FILES {
						break
					}
					return 0, err
				}
			}
		}
		return 0, fmt.Errorf("cannot find %v in running process list", tiExecutableName)
	}

	if !checkIfAdmin() {
		if err := elevate(); err != nil {
			return cmd, fmt.Errorf("cannot elevate Privs: %v", err)
		}
	}

	if err := enableSeDebugPrivilege(); err != nil {
		return cmd, fmt.Errorf("cannot enable %v: %v", seDebugPrivilege, err)
	}

	svcMgr, err := mgr.Connect()
	if err != nil {
		return cmd, fmt.Errorf("cannot connect to svc manager: %v", err)
	}

	n, err := windows.UTF16PtrFromString(tiServiceName)
	if err != nil {
		return cmd, err
	}
	h, err := windows.OpenService(svcMgr.Handle, n, windows.SERVICE_QUERY_STATUS|windows.SERVICE_START|windows.SERVICE_STOP|windows.SERVICE_USER_DEFINED_CONTROL)
	if err != nil {
		return cmd, err
	}
	s := &mgr.Service{Name: tiServiceName, Handle: h}

	status, err := s.Query()
	if err != nil {
		return cmd, fmt.Errorf("cannot query ti service: %v", err)
	}

	if status.State != svc.Running {
		if err := s.Start(); err != nil {
			return cmd, fmt.Errorf("cannot start ti service: %v", err)
		} else {
			defer s.Control(svc.Stop)
		}
	}

	tiPid, err := getTrustedInstallerPid()
	if err != nil {
		return cmd, err
	}

	hand, err := windows.OpenProcess(windows.PROCESS_CREATE_PROCESS|windows.PROCESS_DUP_HANDLE|windows.PROCESS_SET_INFORMATION, true, tiPid)
	if err != nil {
		return cmd, fmt.Errorf("cannot open ti process: %v", err)
	}

	cmd = exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_CONSOLE,
		ParentProcess: syscall.Handle(hand),
		HideWindow:    true,
	}

	err = cmd.Start()
	if err != nil {
		return cmd, fmt.Errorf("cannot start new process: %v", err)
	}

	return cmd, nil
}
