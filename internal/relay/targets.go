package relay

import (
	"bufio"
	"math/rand"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type TargetPool struct {
	mu         sync.Mutex
	all        []*url.URL
	finished   map[string]bool
	randomize  bool
	cursor     int
}

func NewPool(targets []string, randomize bool) (*TargetPool, error) {
	pool := &TargetPool{
		finished:  make(map[string]bool),
		randomize: randomize,
	}
	for _, t := range targets {
		if !strings.Contains(t, "://") {
			t = "smb://" + t
		}
		u, err := url.Parse(t)
		if err != nil {
			return nil, err
		}
		pool.all = append(pool.all, u)
	}
	return pool, nil
}

func PoolFromFile(path string, randomize bool) (*TargetPool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return NewPool(lines, randomize)
}

func (p *TargetPool) Next(noMulti bool) *url.URL {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.all) == 0 {
		return nil
	}

	if p.randomize {
		src := rand.New(rand.NewSource(time.Now().UnixNano()))
		idxs := src.Perm(len(p.all))
		for _, i := range idxs {
			u := p.all[i]
			if !noMulti || !p.finished[u.String()] {
				return u
			}
		}
		return nil
	}

	for range p.all {
		u := p.all[p.cursor%len(p.all)]
		p.cursor++
		if !noMulti || !p.finished[u.String()] {
			return u
		}
	}
	return nil
}

func (p *TargetPool) MarkDone(u *url.URL) {
	p.mu.Lock()
	p.finished[u.String()] = true
	p.mu.Unlock()
}

func (p *TargetPool) All() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.all))
	for i, u := range p.all {
		out[i] = u.String()
	}
	return out
}

// WatchFile monitors a target file and reloads the pool when it changes.
func WatchFile(path string, pool *TargetPool, randomize bool) {
	var prev time.Time
	for {
		time.Sleep(5 * time.Second)
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.ModTime().After(prev) {
			prev = info.ModTime()
			fresh, err := PoolFromFile(path, randomize)
			if err != nil {
				continue
			}
			pool.mu.Lock()
			pool.all = fresh.all
			pool.finished = make(map[string]bool)
			pool.cursor = 0
			pool.mu.Unlock()
		}
	}
}
