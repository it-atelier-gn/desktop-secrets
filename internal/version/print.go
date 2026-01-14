package version

import "log"

func PrintVersion() {
	log.Printf("Version: %s, Revision: %s", Version, Revision)
}
