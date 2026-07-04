package main

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"
)

type HistoryStore struct {
	mu   sync.RWMutex
	path string
}

func NewHistoryStore(path string) *HistoryStore {
	return &HistoryStore{path: path}
}

func (s *HistoryStore) Load() ([]ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return []ScanResult{}, nil
	}
	if err != nil {
		return nil, err
	}

	var results []ScanResult
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	return results, nil
}

func (s *HistoryStore) Append(result ScanResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var results []ScanResult
	data, err := os.ReadFile(s.path)
	if err == nil {
		_ = json.Unmarshal(data, &results)
	}

	// Deduplicate by URL — keep the most recent scan per URL
	filtered := make([]ScanResult, 0, len(results))
	for _, r := range results {
		if r.Url != result.Url {
			filtered = append(filtered, r)
		}
	}

	// Prepend newest, cap at 100 entries
	filtered = append([]ScanResult{result}, filtered...)
	if len(filtered) > 100 {
		filtered = filtered[:100]
	}

	out, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, out, 0644)
}

func historyGetHandler(store *HistoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		results, err := store.Load()
		if err != nil {
			http.Error(w, `{"error":"failed to load history"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(results)
	}
}

func historyDeleteHandler(store *HistoryStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := os.WriteFile(store.path, []byte("[]"), 0644); err != nil {
			http.Error(w, `{"error":"failed to clear history"}`, http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}
}