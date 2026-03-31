package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"

	_ "github.com/lib/pq"
)

var db *sql.DB

const version = "1.4.2"

func main() {
	var err error
	dsn := os.Getenv("DATABASE_URL")
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/version", versionHandler)
	mux.HandleFunc("/diagnostics/ping", diagnosticsPingHandler)
	mux.HandleFunc("/services/search", serviceSearchHandler)
	mux.HandleFunc("/services/health", serviceHealthProxyHandler)

	addr := ":8080"
	log.Printf("monitoring server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// Version endpoint (clean — no vulnerabilities).
func versionHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"version": version,
		"status":  "ok",
	})
}

// @vuln G1: Command injection via unsanitised user input.
// The `host` query parameter is concatenated directly into a shell
// command string.  An attacker can append shell metacharacters
// (e.g., `; cat /etc/passwd`) to execute arbitrary commands on the
// server.
func diagnosticsPingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		http.Error(w, `{"error":"missing host parameter"}`, http.StatusBadRequest)
		return
	}

	cmd := exec.Command("sh", "-c", "ping -c 3 "+host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(
			w,
			fmt.Sprintf(`{"error":"ping failed","details":"%s"}`, string(output)),
			http.StatusInternalServerError,
		)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"host":   host,
		"result": string(output),
	})
}

// @vuln G2: SQL injection via string formatting.
// The `q` query parameter is interpolated directly into a SQL query
// using fmt.Sprintf, allowing an attacker to inject arbitrary SQL
// (e.g., `' UNION SELECT password FROM credentials --`).
func serviceSearchHandler(w http.ResponseWriter, r *http.Request) {
	searchTerm := r.URL.Query().Get("q")
	if searchTerm == "" {
		http.Error(w, `{"error":"missing search term"}`, http.StatusBadRequest)
		return
	}

	query := fmt.Sprintf(
		"SELECT id, name, endpoint, status FROM services WHERE name LIKE '%%%s%%'",
		searchTerm,
	)

	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type service struct {
		ID       int    `json:"id"`
		Name     string `json:"name"`
		Endpoint string `json:"endpoint"`
		Status   string `json:"status"`
	}

	var results []service
	for rows.Next() {
		var s service
		if err := rows.Scan(&s.ID, &s.Name, &s.Endpoint, &s.Status); err != nil {
			continue
		}
		results = append(results, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// @vuln G3: Server-Side Request Forgery (SSRF).
// The `url` query parameter is passed directly to http.Get with no
// validation or allowlist.  An attacker can target internal services
// (e.g., http://169.254.169.254/latest/meta-data/ on AWS) to
// exfiltrate cloud credentials or probe the internal network.
func serviceHealthProxyHandler(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, `{"error":"missing url parameter"}`, http.StatusBadRequest)
		return
	}

	resp, err := http.Get(targetURL)
	if err != nil {
		http.Error(
			w,
			fmt.Sprintf(`{"error":"health check failed","details":"%v"}`, err),
			http.StatusBadGateway,
		)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, `{"error":"failed to read response"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"url":         targetURL,
		"status_code": resp.StatusCode,
		"body":        string(body),
	})
}
