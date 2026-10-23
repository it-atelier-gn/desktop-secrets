//go:build windows

package utils

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

const (
	taskActionExec          = 0
	taskCreateOrUpdate      = 6
	taskLogonInteractive    = 3
	taskRunLevelLUA         = 0
	taskInstancesParallel   = 0
	taskPriorityNormal      = 4
	rpcEChangedMode         = 0x80010106
	scheduledDaemonTaskName = "desktop-secrets daemon"
)

type scheduledTask struct {
	Name        string
	UserID      string
	Path        string
	Arguments   string
	WorkingDir  string
	Description string
}

func startScheduledDaemon(exe string, args, env []string) error {
	return startScheduledTask(scheduledDaemonTaskName, exe, args, env)
}

func startScheduledTask(name, exe string, args, env []string) error {
	user, sid, err := currentUser()
	if err != nil {
		return err
	}
	return runScheduledTask(scheduledTask{
		Name:        name + " " + sid,
		UserID:      user,
		Path:        exe,
		Arguments:   joinArgs(append(args, SetenvArgs(env)...)),
		WorkingDir:  filepath.Dir(exe),
		Description: "Starts the desktop-secrets daemon outside the job object of the calling process.",
	})
}

func joinArgs(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	return strings.Join(quoted, " ")
}

func currentUser() (name, sid string, err error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", "", err
	}
	account, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return "", "", err
	}
	return domain + `\` + account, u.User.Sid.String(), nil
}

type comRefs struct{ vs []*ole.VARIANT }

func (c *comRefs) dispatch(v *ole.VARIANT, err error) (*ole.IDispatch, error) {
	if err != nil {
		return nil, err
	}
	c.vs = append(c.vs, v)
	d := v.ToIDispatch()
	if d == nil {
		return nil, errors.New("task scheduler returned no object")
	}
	return d, nil
}

func (c *comRefs) release() {
	for i := len(c.vs) - 1; i >= 0; i-- {
		_ = c.vs[i].Clear()
	}
}

func put(d *ole.IDispatch, props map[string]any) error {
	for k, v := range props {
		if _, err := oleutil.PutProperty(d, k, v); err != nil {
			return fmt.Errorf("set %s: %w", k, err)
		}
	}
	return nil
}

func runScheduledTask(t scheduledTask) error {
	return withScheduler(func(svc *ole.IDispatch) error { return registerAndRun(svc, t) })
}

func withScheduler(fn func(svc *ole.IDispatch) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		var oe *ole.OleError
		if !errors.As(err, &oe) || (oe.Code() != 1 && uint32(oe.Code()) != rpcEChangedMode) {
			return fmt.Errorf("task scheduler: CoInitializeEx: %w", err)
		}
		if oe.Code() == 1 {
			defer ole.CoUninitialize()
		}
	} else {
		defer ole.CoUninitialize()
	}

	unk, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		return fmt.Errorf("task scheduler: %w", err)
	}
	defer unk.Release()
	svc, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return fmt.Errorf("task scheduler: %w", err)
	}
	defer svc.Release()

	if _, err := oleutil.CallMethod(svc, "Connect"); err != nil {
		return fmt.Errorf("task scheduler: connect: %w", err)
	}
	if err := fn(svc); err != nil {
		return fmt.Errorf("task scheduler: %w", err)
	}
	return nil
}

func registerAndRun(svc *ole.IDispatch, t scheduledTask) error {
	var refs comRefs
	defer refs.release()

	folder, err := refs.dispatch(oleutil.CallMethod(svc, "GetFolder", `\`))
	if err != nil {
		return fmt.Errorf("open root folder: %w", err)
	}
	def, err := refs.dispatch(oleutil.CallMethod(svc, "NewTask", 0))
	if err != nil {
		return fmt.Errorf("new task: %w", err)
	}

	info, err := refs.dispatch(oleutil.GetProperty(def, "RegistrationInfo"))
	if err != nil {
		return err
	}
	if err := put(info, map[string]any{"Description": t.Description}); err != nil {
		return err
	}

	principal, err := refs.dispatch(oleutil.GetProperty(def, "Principal"))
	if err != nil {
		return err
	}
	if err := put(principal, map[string]any{
		"UserId":    t.UserID,
		"LogonType": taskLogonInteractive,
		"RunLevel":  taskRunLevelLUA,
	}); err != nil {
		return err
	}

	settings, err := refs.dispatch(oleutil.GetProperty(def, "Settings"))
	if err != nil {
		return err
	}
	if err := put(settings, map[string]any{
		"Enabled":                    true,
		"Hidden":                     true,
		"AllowDemandStart":           true,
		"AllowHardTerminate":         true,
		"DisallowStartIfOnBatteries": false,
		"StopIfGoingOnBatteries":     false,
		"ExecutionTimeLimit":         "PT0S",
		"MultipleInstances":          taskInstancesParallel,
		"Priority":                   taskPriorityNormal,
	}); err != nil {
		return err
	}

	actions, err := refs.dispatch(oleutil.GetProperty(def, "Actions"))
	if err != nil {
		return err
	}
	action, err := refs.dispatch(oleutil.CallMethod(actions, "Create", taskActionExec))
	if err != nil {
		return fmt.Errorf("create action: %w", err)
	}
	if err := put(action, map[string]any{
		"Path":             t.Path,
		"Arguments":        t.Arguments,
		"WorkingDirectory": t.WorkingDir,
	}); err != nil {
		return err
	}

	task, err := refs.dispatch(oleutil.CallMethod(folder, "RegisterTaskDefinition",
		t.Name, def, taskCreateOrUpdate, t.UserID, nil, taskLogonInteractive, ""))
	if err != nil {
		return fmt.Errorf("register task %q: %w", t.Name, err)
	}
	if _, err := refs.dispatch(oleutil.CallMethod(task, "Run", nil)); err != nil {
		return fmt.Errorf("run task %q: %w", t.Name, err)
	}
	return nil
}
