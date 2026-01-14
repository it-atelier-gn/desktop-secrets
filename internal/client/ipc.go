package client

import (
	"desktopsecrets/internal/shm"
	"encoding/json"
	"fmt"
)

func readStateFromShm() (*shm.DaemonState, error) {
	b, err := shm.ShmClientRead()
	if err != nil {
		return nil, err
	}
	var st shm.DaemonState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	if st.Port <= 0 || st.Token == "" {
		return nil, fmt.Errorf("invalid state in shm")
	}
	return &st, nil
}
