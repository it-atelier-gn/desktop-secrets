package server

import (
	"testing"
	"time"
)

type ttlRecordingAWS struct {
	fakeAWSResolver
	ttl time.Duration
}

func (f *ttlRecordingAWS) SetTTL(ttl time.Duration) { f.ttl = ttl }

func TestSetTTLReachesProviderCaches(t *testing.T) {
	aws := &ttlRecordingAWS{}
	app := newTestApp(nil, nil, nil, aws, nil, nil, nil)
	app.setTTL(30 * time.Minute)
	if got := app.UnlockTTL.Load(); got != 30*time.Minute {
		t.Errorf("UnlockTTL = %v, want 30m", got)
	}
	if aws.ttl != 30*time.Minute {
		t.Errorf("provider TTL = %v, want 30m", aws.ttl)
	}
}
