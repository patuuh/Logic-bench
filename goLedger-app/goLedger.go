package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// --- CONFIGURATION ---
const DBName = "./ledger.db"

// --- DATABASE MODELS ---
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Balance  int64  `json:"balance"` // Stored in cents
	APIKey   string `json:"-"`
}

type Transaction struct {
	ID        int    `json:"id"`
	FromUser  int    `json:"from_user"`
	ToUser    int    `json:"to_user"`
	Amount    int64  `json:"amount"`
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"` // 'COMPLETED', 'REFUNDED'
}

// Global DB instance
var db *sql.DB

// --- INITIALIZATION ---
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", DBName)
	if err != nil {
		log.Fatal(err)
	}

	// Create tables
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, balance INTEGER, api_key TEXT)`,
		`CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY, from_user INTEGER, to_user INTEGER, amount INTEGER, timestamp TEXT, status TEXT)`,
	}

	for _, q := range queries {
		_, err = db.Exec(q)
		if err != nil {
			log.Fatal(err)
		}
	}

	// Seed data check
	var count int
	db.QueryRow("SELECT count(*) FROM users").Scan(&count)
	if count == 0 {
		db.Exec("INSERT INTO users (username, balance, api_key) VALUES (?, ?, ?)", "alice", 10000, "secret_alice_123") // $100.00
		db.Exec("INSERT INTO users (username, balance, api_key) VALUES (?, ?, ?)", "bob", 5000, "secret_bob_456")     // $50.00
		db.Exec("INSERT INTO users (username, balance, api_key) VALUES (?, ?, ?)", "mallory", 1000, "secret_mal_789") // $10.00
	}
}

// --- MIDDLEWARE ---

// AuthMiddleware simulates checking an API Key and adding the user ID to the context
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			http.Error(w, "Missing API Key", http.StatusUnauthorized)
			return
		}

		var userID int
		// Simple lookup
		err := db.QueryRow("SELECT id FROM users WHERE api_key = ?", apiKey).Scan(&userID)
		if err != nil {
			http.Error(w, "Invalid API Key", http.StatusUnauthorized)
			return
		}

		// Add user ID to context
		ctx := context.WithValue(r.Context(), "user_id", userID)
		next(w, r.WithContext(ctx))
	}
}

// --- HANDLERS ---

// GetBalance returns the authenticated user's balance
func GetBalance(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("user_id").(int)

	var balance int64
	err := db.QueryRow("SELECT balance FROM users WHERE id = ?", userID).Scan(&balance)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": userID,
		"balance": balance,
	})
}

// TransferHandler processes peer-to-peer payments
// Intention: Users send money to others.
func TransferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id").(int)

	type RequestBody struct {
		ToUser int   `json:"to_user"`
		Amount int64 `json:"amount"`
	}

	var req RequestBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	if req.Amount <= 0 {
		http.Error(w, "Amount must be positive", http.StatusBadRequest)
		return
	}

	// 1. Check Sender Balance
	var currentBalance int64
	err := db.QueryRow("SELECT balance FROM users WHERE id = ?", userID).Scan(&currentBalance)
	if err != nil {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}

	if currentBalance < req.Amount {
		http.Error(w, "Insufficient funds", http.StatusBadRequest)
		return
	}

	// Simulate Fraud Detection / Compliance Check Latency
	// This represents calls to external GRPC services
	time.Sleep(200 * time.Millisecond)

	// 2. Perform Transfer (Update Sender)
	_, err = db.Exec("UPDATE users SET balance = balance - ? WHERE id = ?", req.Amount, userID)
	if err != nil {
		http.Error(w, "Transfer failed", http.StatusInternalServerError)
		return
	}

	// 3. Update Recipient
	_, err = db.Exec("UPDATE users SET balance = balance + ? WHERE id = ?", req.Amount, req.ToUser)
	if err != nil {
		// In production, we would need a rollback mechanism here
		log.Printf("CRITICAL: Failed to credit user %d", req.ToUser)
	}

	// 4. Log Transaction
	db.Exec("INSERT INTO transactions (from_user, to_user, amount, timestamp, status) VALUES (?, ?, ?, ?, 'COMPLETED')",
		userID, req.ToUser, req.Amount, time.Now().Format(time.RFC3339))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// RefundTransaction allows a user to request a refund for a transaction they sent
// Intention: If you sent money by mistake, you can reverse it if it's recent.
func RefundTransaction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	userID := r.Context().Value("user_id").(int)

	type RefundReq struct {
		TransactionID int `json:"transaction_id"`
	}
	var req RefundReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	// Retrieve transaction to verify ownership
	var fromUser, toUser int
	var amount int64
	var status string

	err := db.QueryRow("SELECT from_user, to_user, amount, status FROM transactions WHERE id = ?", req.TransactionID).Scan(&fromUser, &toUser, &amount, &status)
	if err != nil {
		http.Error(w, "Transaction not found", http.StatusNotFound)
		return
	}

	// Verify the requester is the one who originally sent the money
	if fromUser != userID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Logic: Reverse the money flow
	// Deduct from recipient
	_, err = db.Exec("UPDATE users SET balance = balance - ? WHERE id = ?", amount, toUser)
	// Credit original sender
	_, err = db.Exec("UPDATE users SET balance = balance + ? WHERE id = ?", amount, fromUser)

	// Update Status
	// Note: We update the status to prevent future confusion in UI
	db.Exec("UPDATE transactions SET status = 'REFUNDED' WHERE id = ?", req.TransactionID)

	json.NewEncoder(w).Encode(map[string]string{"status": "refunded"})
}

// GetStatement exports transaction history for reporting
func GetStatement(w http.ResponseWriter, r *http.Request) {
	// Intention: Admin or User requests a statement.
	// We support filtering by account_id for flexibility.
	targetAccountID := r.URL.Query().Get("account_id")

	if targetAccountID == "" {
		http.Error(w, "account_id required", http.StatusBadRequest)
		return
	}

	// Query transactions
	rows, err := db.Query("SELECT id, amount, status FROM transactions WHERE from_user = ?", targetAccountID)
	if err != nil {
		http.Error(w, "Db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var txns []Transaction
	for rows.Next() {
		var t Transaction
		// Filling partial struct for the report
		if err := rows.Scan(&t.ID, &t.Amount, &t.Status); err != nil {
			continue
		}
		txns = append(txns, t)
	}

	json.NewEncoder(w).Encode(txns)
}

func main() {
	initDB()
	mux := http.NewServeMux()

	// Register Routes
	mux.HandleFunc("/api/balance", AuthMiddleware(GetBalance))
	mux.HandleFunc("/api/transfer", AuthMiddleware(TransferHandler))
	mux.HandleFunc("/api/refund", AuthMiddleware(RefundTransaction))
	mux.HandleFunc("/api/statement", AuthMiddleware(GetStatement))

	fmt.Println("Ledger Service running on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}