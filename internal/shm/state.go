package shm

type DaemonState struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
	PID      int    `json:"pid"`
}
