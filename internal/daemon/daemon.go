package daemon

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/Eliahhango/OmniScan/internal/db"
	"github.com/Eliahhango/OmniScan/internal/scanner"
	"github.com/Eliahhango/OmniScan/pkg/types"
	"golang.org/x/net/websocket"
)

//go:embed web/*
var webFS embed.FS

type Server struct {
	cfg        *scanner.OrchestratorConfig
	store      *db.Store
	listen     string
	wsClients  map[*websocket.Conn]bool
	wsMu       sync.Mutex
	httpServer *http.Server
}

func New(cfg *scanner.OrchestratorConfig, store *db.Store, listen string) *Server {
	return &Server{
		cfg:       cfg,
		store:     store,
		listen:    listen,
		wsClients: make(map[*websocket.Conn]bool),
	}
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/scans", s.handleScans)
	mux.HandleFunc("/api/scans/", s.handleScanFindings)
	mux.HandleFunc("/api/diff", s.handleDiff)
	mux.Handle("/ws", websocket.Handler(s.handleWS))

	mux.Handle("/", http.FileServer(http.FS(webFS)))

	s.httpServer = &http.Server{Addr: s.listen, Handler: mux}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(shutdownCtx)
	}()

	log.Printf("OmniScan daemon (EliTechWiz/github.com/Eliahhango) listening on %s", s.listen)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) Broadcast(finding types.Finding) {
	data, err := json.Marshal(finding)
	if err != nil {
		return
	}
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	for ws := range s.wsClients {
		ws.Write(data)
	}
}

func (s *Server) handleWS(ws *websocket.Conn) {
	s.wsMu.Lock()
	s.wsClients[ws] = true
	s.wsMu.Unlock()

	var buf [1024]byte
	for {
		_, err := ws.Read(buf[:])
		if err != nil {
			break
		}
	}

	s.wsMu.Lock()
	delete(s.wsClients, ws)
	s.wsMu.Unlock()
	ws.Close()
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	scans, err := s.store.ListScans()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, scans)
}

func (s *Server) handleScanFindings(w http.ResponseWriter, r *http.Request) {
	var scanID int64
	if _, err := fmt.Sscanf(r.URL.Path, "/api/scans/%d", &scanID); err != nil {
		http.Error(w, "invalid scan ID", http.StatusBadRequest)
		return
	}
	findings, err := s.store.GetFindings(scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, findings)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	id1Str := r.URL.Query().Get("id1")
	id2Str := r.URL.Query().Get("id2")
	if id1Str == "" || id2Str == "" {
		http.Error(w, "id1 and id2 query params required", http.StatusBadRequest)
		return
	}
	var id1, id2 int64
	if _, err := fmt.Sscanf(id1Str, "%d", &id1); err != nil {
		http.Error(w, "invalid id1", http.StatusBadRequest)
		return
	}
	if _, err := fmt.Sscanf(id2Str, "%d", &id2); err != nil {
		http.Error(w, "invalid id2", http.StatusBadRequest)
		return
	}

	diff := computeDiff(s.store, id1, id2)
	writeJSON(w, diff)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

type DiffResult struct {
	Scan1ID      int64           `json:"scan1_id"`
	Scan2ID      int64           `json:"scan2_id"`
	NewFindings  []types.Finding `json:"new_findings"`
	FixedFindings []types.Finding `json:"fixed_findings"`
	SeverityDelta map[string]int `json:"severity_delta"`
}

func computeDiff(store *db.Store, id1, id2 int64) *DiffResult {
	f1, _ := store.GetFindings(id1)
	f2, _ := store.GetFindings(id2)

	f1set := make(map[string]bool, len(f1))
	for _, f := range f1 {
		f1set[f.ID] = true
	}
	f2set := make(map[string]bool, len(f2))
	for _, f := range f2 {
		f2set[f.ID] = true
	}

	result := &DiffResult{
		Scan1ID:       id1,
		Scan2ID:       id2,
		SeverityDelta: make(map[string]int),
	}

	for _, f := range f2 {
		if !f1set[f.ID] {
			result.NewFindings = append(result.NewFindings, f)
			result.SeverityDelta[string(f.Severity)]++
		}
	}

	for _, f := range f1 {
		if !f2set[f.ID] {
			result.FixedFindings = append(result.FixedFindings, f)
			result.SeverityDelta[string(f.Severity)]--
		}
	}

	return result
}

func RunScanAsync(ctx context.Context, cfg *scanner.OrchestratorConfig, store *db.Store) (*scanner.Orchestrator, error) {
	orch := scanner.NewOrchestrator(cfg, store)
	go func() {
		if err := orch.Run(ctx); err != nil {
			log.Printf("scan error: %v", err)
		}
	}()
	return orch, nil
}
