package client

import (
	"encoding/json"
	"fmt"

	"github.com/it-atelier-gn/desktop-secrets/internal/shm"
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
	if st.Endpoint == "" || st.Token == "" {
		return nil, fmt.Errorf("invalid state in shm")
	}
	return &st, nil
}
