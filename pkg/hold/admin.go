package hold

import (
	"encoding/json"
	"net/http"
	"strings"
)

// RegisterAdminHandlers adds hold management endpoints to the admin mux.
//
//	GET  /admin/holds          — list all pending holds
//	GET  /admin/holds/{id}     — get a specific hold
//	POST /admin/holds/{id}/approve — approve a held request
//	POST /admin/holds/{id}/deny    — deny a held request
//	GET  /admin/holds/history  — list recently resolved holds
func RegisterAdminHandlers(mux *http.ServeMux, mgr *Manager) {
	mux.HandleFunc("/admin/holds", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, mgr.List())
	})

	mux.HandleFunc("/admin/holds/history", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writeJSON(w, mgr.History())
	})

	mux.HandleFunc("/admin/holds/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/admin/holds/")
		parts := strings.Split(path, "/")

		if len(parts) == 0 || parts[0] == "" {
			http.Error(w, "hold ID required", http.StatusBadRequest)
			return
		}

		holdID := parts[0]

		if len(parts) == 1 {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			req, ok := mgr.Get(holdID)
			if !ok {
				http.Error(w, "hold not found", http.StatusNotFound)
				return
			}
			writeJSON(w, req)
			return
		}

		action := parts[1]
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		approver := r.Header.Get("X-Approver")
		if approver == "" {
			approver = "admin-api"
		}

		switch action {
		case "approve":
			if err := mgr.Approve(holdID, approver); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, map[string]string{"status": "approved", "hold": holdID})

		case "deny":
			if err := mgr.Deny(holdID, approver); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			writeJSON(w, map[string]string{"status": "denied", "hold": holdID})

		default:
			http.Error(w, "unknown action: "+action, http.StatusBadRequest)
		}
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
