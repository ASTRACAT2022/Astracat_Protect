package limits

import (
	"sync"
	"time"
)

type penaltyEntry struct {
	count      int
	windowFrom time.Time
	bannedTill time.Time
}

type PenaltyBox struct {
	mu        sync.Mutex
	entries   map[string]*penaltyEntry
	threshold int
	window    time.Duration
	banFor    time.Duration
}

func NewPenaltyBox(threshold int, window, banFor time.Duration) *PenaltyBox {
	return &PenaltyBox{
		entries:   map[string]*penaltyEntry{},
		threshold: threshold,
		window:    window,
		banFor:    banFor,
	}
}

func (pb *PenaltyBox) enabled() bool {
	return pb != nil && pb.threshold > 0 && pb.window > 0 && pb.banFor > 0
}

func (pb *PenaltyBox) IsBanned(key string) (bool, time.Time) {
	if !pb.enabled() {
		return false, time.Time{}
	}
	pb.mu.Lock()
	defer pb.mu.Unlock()
	now := time.Now()
	e := pb.entries[key]
	if e == nil || now.After(e.bannedTill) {
		return false, time.Time{}
	}
	return true, e.bannedTill
}

func (pb *PenaltyBox) RegisterFailure(key string) (bool, time.Time) {
	if !pb.enabled() {
		return false, time.Time{}
	}
	pb.mu.Lock()
	defer pb.mu.Unlock()

	now := time.Now()
	e := pb.entries[key]
	if e == nil {
		e = &penaltyEntry{windowFrom: now}
		pb.entries[key] = e
	}
	if now.Before(e.bannedTill) {
		return true, e.bannedTill
	}
	if now.Sub(e.windowFrom) > pb.window {
		e.windowFrom = now
		e.count = 0
	}
	e.count++
	if e.count >= pb.threshold {
		e.bannedTill = now.Add(pb.banFor)
		e.count = 0
		e.windowFrom = now
		return true, e.bannedTill
	}
	return false, time.Time{}
}

func (pb *PenaltyBox) RegisterBan(key string, duration time.Duration) {
	if pb == nil || duration <= 0 {
		return
	}
	pb.mu.Lock()
	defer pb.mu.Unlock()

	now := time.Now()
	e := pb.entries[key]
	if e == nil {
		e = &penaltyEntry{windowFrom: now}
		pb.entries[key] = e
	}
	e.bannedTill = now.Add(duration)
	e.count = 0
	e.windowFrom = now
}

func (pb *PenaltyBox) Cleanup() {
	if pb == nil {
		return
	}
	pb.mu.Lock()
	defer pb.mu.Unlock()

	now := time.Now()
	for k, v := range pb.entries {
		if now.After(v.bannedTill) && now.Sub(v.windowFrom) > pb.window*2 {
			delete(pb.entries, k)
		}
	}
}
