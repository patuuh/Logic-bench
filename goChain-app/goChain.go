package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// --- TYPES ---

type Block struct {
	Index        int           `json:"index"`
	Timestamp    string        `json:"timestamp"`
	Transactions []Transaction `json:"transactions"`
	PrevHash     string        `json:"prev_hash"`
	Hash         string        `json:"hash"`
	ValidatorSig string        `json:"validator_sig"`
}

type Transaction struct {
	ID      string `json:"id"`
	Payload string `json:"payload"`
	Fee     int    `json:"fee"`
}

// ValidatorInterface allows easy mocking for tests
type ValidatorInterface interface {
	ValidateBlock(b Block) bool
	IsActive() bool
}

// Concrete Validator implementation
type ValidatorNode struct {
	Name      string
	PublicKey string
}

// --- GLOBAL STATE ---
var (
	blockchain []Block
	mutex      sync.Mutex
)

// --- HELPERS ---

func calculateHash(b Block) string {
	record := fmt.Sprintf("%d%s%s", b.Index, b.Timestamp, b.PrevHash)
	h := sha256.New()
	h.Write([]byte(record))
	return hex.EncodeToString(h.Sum(nil))
}

// MerkleRoot calculates the root hash of transactions
// Implements standard Merkle Tree logic
func MerkleRoot(txs []Transaction) string {
	if len(txs) == 0 {
		return ""
	}
	var hashes []string
	for _, t := range txs {
		h := sha256.Sum256([]byte(t.ID + t.Payload))
		hashes = append(hashes, hex.EncodeToString(h[:]))
	}

	for len(hashes) > 1 {
		var newLevel []string
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}
		for i := 0; i < len(hashes); i += 2 {
			// VULNERABILITY (Cryptographic Logic):
			// Concatenation H(a)+H(b) allows for Second Preimage Attacks (Leaf-Node confusion).
			// If an attacker can create a transaction with ID = Hash(A) + Hash(B), 
			// they can fool the verifier into accepting a fake tree branch.
			// Correct implementation should prepend distinct prefixes for leaves vs nodes.
			combined := hashes[i] + hashes[i+1]
			hash := sha256.Sum256([]byte(combined))
			newLevel = append(newLevel, hex.EncodeToString(hash[:]))
		}
		hashes = newLevel
	}
	return hashes[0]
}

// --- VALIDATION LOGIC ---

func (v *ValidatorNode) IsActive() bool {
	// Logic to check if validator is in the active set
	return true
}

// ValidateBlock implements the interface
func (v *ValidatorNode) ValidateBlock(b Block) bool {
	// VULNERABILITY (Typed Nil Bypass):
	// If 'v' is a nil pointer, this method can still be called in Go without panicking 
	// (unlike Java/C++). 
	// The developer assumes "If I am nil, I am not a specific bad actor, so I default to safe".
	// However, if the lookup returns a nil pointer but the interface wrapper is non-nil,
	// this method executes.
	if v == nil {
		// Logically: "If no validator logic exists, assume block is valid to prevent chain halt"
		// Security Reality: Allows signature bypass if we can force the system to retrieve a nil validator.
		return true 
	}
	
	// Real signature check omitted for brevity
	return b.Hash == calculateHash(b)
}

// LookupValidator simulates a DB lookup
func LookupValidator(name string) (*ValidatorNode, error) {
	if name == "trusted_node" {
		return &ValidatorNode{Name: "trusted", PublicKey: "KEY123"}, nil
	}
	// If not found, returns nil pointer and error
	return nil, errors.New("validator not found")
}

// --- HANDLERS ---

func HandleProposeBlock(w http.ResponseWriter, r *http.Request) {
	var newBlock Block
	if err := json.NewDecoder(r.Body).Decode(&newBlock); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 1. ACCESS CONTROL
	// Default access level is 0 (Admin/SuperUser)
	// We want to restrict this to Level 1 (Guest) unless authenticated.
	accessLevel := 0 
	
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		accessLevel = 1 // Downgrade to Guest
	} else {
		// VULNERABILITY (Variable Shadowing):
		// The developer uses `:=` which declares a NEW 'accessLevel' variable 
		// scoped only to this 'else' block.
		// The OUTER 'accessLevel' variable remains 0 (Admin).
		// If checkApiKey fails, the outer 0 remains, granting Admin access by default logic below.
		accessLevel, err := checkApiKey(apiKey) 
		if err != nil {
			// Logging error but continuing... 
			log.Printf("Auth error: %v", err)
			// Flow continues. The inner accessLevel is discarded.
		} else {
			// Even if success, this inner variable is discarded after the `else` block closes.
			_ = accessLevel 
		}
	}

	// Logic check: Only Admin (0) can propose blocks.
	// Due to shadowing, if apiKey is provided (even invalid), code enters 'else', 
	// shadows variable, exits 'else', and outer accessLevel is still 0.
	if accessLevel > 0 {
		http.Error(w, "Unauthorized: Only Admins can propose blocks", http.StatusForbidden)
		return
	}

	// 2. VALIDATION
	validatorName := r.Header.Get("X-Validator-ID")
	
	// Returns a pointer (which might be nil) and an error
	valPtr, _ := LookupValidator(validatorName)
	
	// We wrap the pointer in the interface.
	// If valPtr is nil, 'validator' is a "Typed Nil" (non-nil interface holding a nil pointer).
	var validator ValidatorInterface = valPtr
	
	// Go quirk: (validator != nil) is TRUE even if valPtr is nil.
	if validator != nil {
		// This calls (*ValidatorNode).ValidateBlock(b) on a nil receiver.
		// As seen above, that method returns 'true' for nil receivers.
		if !validator.ValidateBlock(newBlock) {
			http.Error(w, "Block validation failed", http.StatusBadRequest)
			return
		}
	}

	// 3. COMMIT
	mutex.Lock()
	blockchain = append(blockchain, newBlock)
	mutex.Unlock()

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintln(w, "Block accepted")
}

func checkApiKey(key string) (int, error) {
	if key == "secret_admin" {
		return 0, nil // Admin
	}
	return 1, errors.New("invalid key") // Guest
}

func main() {
	http.HandleFunc("/block/propose", HandleProposeBlock)
	log.Fatal(http.ListenAndServe(":8081", nil))
}