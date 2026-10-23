//go:build windows

package memprotect

import (
	"fmt"

	"golang.org/x/sys/windows"
)

const allowedProcessAccess = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_QUERY_LIMITED_INFORMATION |
	windows.SYNCHRONIZE | windows.PROCESS_TERMINATE | windows.READ_CONTROL

func HardenProcess() error {
	acl, err := hardenedProcessACL()
	if err != nil {
		return err
	}
	err = windows.SetSecurityInfo(windows.CurrentProcess(), windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	if err != nil {
		return fmt.Errorf("memprotect: set process DACL: %w", err)
	}
	return nil
}

func hardenedProcessACL() (*windows.ACL, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("memprotect: current user: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return nil, err
	}
	grant := func(sid *windows.SID, mask windows.ACCESS_MASK, kind windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  kind,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		grant(u.User.Sid, allowedProcessAccess, windows.TRUSTEE_IS_USER),
		grant(system, allowedProcessAccess, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		grant(ownerRights, windows.READ_CONTROL, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("memprotect: build process DACL: %w", err)
	}
	return acl, nil
}
