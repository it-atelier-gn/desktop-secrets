package cacheinfo

import "time"

type Entry struct {
	Key     string
	Expires time.Time
}
