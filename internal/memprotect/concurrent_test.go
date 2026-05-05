package memprotect

import (
	"fmt"
	"sync"
	"testing"
)

func TestSealConcurrent(t *testing.T) {
	const goroutines = 32
	const opsPerG = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*opsPerG)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerG; i++ {
				want := fmt.Sprintf("g%d-op%d-secret", id, i)
				s, err := SealString(want)
				if err != nil {
					errs <- err
					return
				}
				got, err := s.OpenString()
				if err != nil {
					errs <- err
					return
				}
				if got != want {
					errs <- fmt.Errorf("got %q want %q", got, want)
					return
				}
				s.Destroy()
			}
		}(g)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestOpenAfterDestroyReturnsError(t *testing.T) {
	s, err := SealString("x")
	if err != nil {
		t.Fatal(err)
	}
	s.Destroy()

	if _, err := s.Open(); err == nil {
		t.Fatal("Open after Destroy should error")
	}
	if _, err := s.OpenString(); err == nil {
		t.Fatal("OpenString after Destroy should error")
	}
}

func TestNilSealedSafe(t *testing.T) {
	var s *Sealed
	s.Destroy() // must not panic
	if _, err := s.Open(); err == nil {
		t.Fatal("Open on nil should error")
	}
}

func BenchmarkSealOpen(b *testing.B) {
	plaintext := []byte("benchmark-secret-value-with-some-length")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := Seal(plaintext)
		if err != nil {
			b.Fatal(err)
		}
		pt, err := s.Open()
		if err != nil {
			b.Fatal(err)
		}
		Wipe(pt)
		s.Destroy()
	}
}
