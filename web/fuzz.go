package web

import (
	"regexp"
	"sort"
	"sync"
)

type FuzzHit struct {
	Word   string
	Status int
	Length int
}

type FuzzFilter func(*Response) bool

func MatchStatus(codes ...int) FuzzFilter {
	return func(r *Response) bool {
		for _, c := range codes {
			if r.StatusCode == c {
				return true
			}
		}
		return false
	}
}

func FilterStatus(codes ...int) FuzzFilter {
	m := MatchStatus(codes...)
	return func(r *Response) bool { return !m(r) }
}

func MatchLength(n int) FuzzFilter {
	return func(r *Response) bool { return len(r.Body) == n }
}

func FilterLength(n int) FuzzFilter {
	return func(r *Response) bool { return len(r.Body) != n }
}

func MatchRegex(pattern string) FuzzFilter {
	re := regexp.MustCompile(pattern)
	return func(r *Response) bool { return re.Match(r.Body) }
}

func FilterRegex(pattern string) FuzzFilter {
	re := regexp.MustCompile(pattern)
	return func(r *Response) bool { return !re.Match(r.Body) }
}

type Fuzzer struct {
	Workers int
}

func Fuzz(send func(word string) *Response, wordlist []string, filters ...FuzzFilter) []FuzzHit {
	return (&Fuzzer{Workers: 20}).Run(send, wordlist, filters...)
}

func (f *Fuzzer) Run(send func(word string) *Response, wordlist []string, filters ...FuzzFilter) []FuzzHit {
	workers := f.Workers
	if workers < 1 {
		workers = 1
	}

	type job struct {
		idx  int
		word string
	}
	type hit struct {
		idx int
		h   FuzzHit
	}

	jobs := make(chan job)
	out := make(chan hit, workers)

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				resp := send(j.word)
				if resp == nil {
					continue
				}
				keep := true
				for _, flt := range filters {
					if !flt(resp) {
						keep = false
						break
					}
				}
				if keep {
					out <- hit{idx: j.idx, h: FuzzHit{Word: j.word, Status: resp.StatusCode, Length: len(resp.Body)}}
				}
			}
		}()
	}

	go func() {
		for i, word := range wordlist {
			jobs <- job{idx: i, word: word}
		}
		close(jobs)
	}()
	go func() {
		wg.Wait()
		close(out)
	}()

	var hits []hit
	for h := range out {
		hits = append(hits, h)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].idx < hits[j].idx })

	res := make([]FuzzHit, len(hits))
	for i, h := range hits {
		res[i] = h.h
	}
	return res
}
