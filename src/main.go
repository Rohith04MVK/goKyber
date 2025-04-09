package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	gokyber "github.com/Rohith04MVK/goKyber/goKyber"
)

type User struct {
	Name      string
	PublicKey []byte
	Password  string // Added password field for authentication
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ApiResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func main() {
	users := make(map[string]User)
	reader := bufio.NewReader(os.Stdin)

	os.Mkdir("private_keys", 0700)
	loadUsersFromCSV(users)

	// Start web server in a goroutine
	go startWebServer(users)

	cliMode(users, reader)
}

func cliMode(users map[string]User, reader *bufio.Reader) {
	for {
		fmt.Println("\nOptions: (1) Create User, (2) Send Message, (3) Decrypt Message, (4) Exit")
		fmt.Print("Enter choice: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			createUser(users, reader)
		case "2":
			sendMessage(users, reader)
		case "3":
			decryptMessage(reader)
		case "4":
			fmt.Println("Exiting.")
			return
		default:
			fmt.Println("Invalid choice.")
		}
	}
}

func startWebServer(users map[string]User) {
	// Create a middleware that adds CORS headers
	corsMiddleware := func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization")

			// Handle preflight OPTIONS requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			handler.ServeHTTP(w, r)
		})
	}

	// Serve static files from the frontend directory
	fs := http.FileServer(http.Dir("frontend"))
	http.Handle("/", corsMiddleware(fs))

	// API endpoints with CORS middleware
	http.HandleFunc("/api/register", func(w http.ResponseWriter, r *http.Request) {
		// Add CORS headers directly to API handlers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization")

		// Handle preflight OPTIONS requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		registerHandler(w, r, users)
	})

	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		// Add CORS headers directly to API handlers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization")

		// Handle preflight OPTIONS requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		loginHandler(w, r, users)
	})

	fmt.Println("Starting web server on port 8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error starting server:", err)
	}
}

func registerHandler(w http.ResponseWriter, r *http.Request, users map[string]User) {
	// Set content type for all responses
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "Only POST method is supported"})
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "Invalid request format"})
		return
	}

	if req.Username == "" || req.Password == "" {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "Username and password are required"})
		return
	}

	// Check if user already exists
	if userExistsInCSV(req.Username) {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "Username already exists"})
		return
	}

	// Hash the password
	hashedPassword := hashPassword(req.Password)

	// Generate Kyber key pair
	privateKey, publicKey, err := gokyber.KemKeypair(768)
	if err != nil {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "Error generating key pair"})
		return
	}

	// Save private key
	privateKeyFilename := filepath.Join("private_keys", req.Username+".key")
	if err := os.WriteFile(privateKeyFilename, privateKey, 0600); err != nil {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "Error saving private key"})
		return
	}

	// Create and save user
	users[req.Username] = User{Name: req.Username, PublicKey: publicKey, Password: hashedPassword}
	saveUsersToCSV(users)

	json.NewEncoder(w).Encode(ApiResponse{Success: true, Message: "User registered successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request, users map[string]User) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "POST" {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "Only POST method is supported"})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "Invalid request format"})
		return
	}

	// Reload users to ensure up-to-date data
	users = make(map[string]User)
	loadUsersFromCSV(users)

	user, exists := users[req.Username]
	if !exists {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "User not found"})
		return
	}

	// Check password
	hashedPassword := hashPassword(req.Password)
	if user.Password != hashedPassword {
		json.NewEncoder(w).Encode(ApiResponse{Success: false, Message: "Invalid password"})
		return
	}

	json.NewEncoder(w).Encode(ApiResponse{Success: true, Message: "Login successful"})
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func createUser(users map[string]User, reader *bufio.Reader) {
	fmt.Print("Enter username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Enter password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)
	hashedPassword := hashPassword(password)

	privateKey, publicKey, err := gokyber.KemKeypair(768)
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}

	privateKeyFilename := filepath.Join("private_keys", username+".key")
	err = os.WriteFile(privateKeyFilename, privateKey, 0600)
	if err != nil {
		fmt.Println("Error saving private key:", err)
		return
	}

	users[username] = User{Name: username, PublicKey: publicKey, Password: hashedPassword}

	fmt.Println("User created. Public key stored. Private key saved to", privateKeyFilename)
	saveUsersToCSV(users)
}

func sendMessage(users map[string]User, reader *bufio.Reader) {
	fmt.Print("Enter receiver username: ")
	receiverName, _ := reader.ReadString('\n')
	receiverName = strings.TrimSpace(receiverName)

	// Reload users from CSV to ensure up-to-date data
	users = make(map[string]User)
	loadUsersFromCSV(users)

	receiver, ok := users[receiverName]
	if !ok {
		fmt.Println("Receiver not found.")
		return
	}

	ciphertext, sharedSecret, err := gokyber.KemEncrypt(receiver.PublicKey, 768)
	if err != nil {
		fmt.Println("Error encrypting:", err)
		return
	}

	fmt.Printf("Ciphertext: %x\n\n", ciphertext)
	fmt.Printf("Shared secret: %x\n", sharedSecret)
}

func decryptMessage(reader *bufio.Reader) {
	fmt.Print("Enter username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	// Load users to check password
	users := make(map[string]User)
	loadUsersFromCSV(users)

	user, exists := users[username]
	if !exists {
		fmt.Println("User not found.")
		return
	}

	// Ask for password and verify
	fmt.Print("Enter password: ")
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	// Check if password matches
	hashedPassword := hashPassword(password)
	if user.Password != hashedPassword {
		fmt.Println("Invalid password. Access denied.")
		return
	}

	privateKeyFilename := filepath.Join("private_keys", username+".key")
	privateKey, err := os.ReadFile(privateKeyFilename)
	if err != nil {
		fmt.Println("Error reading private key:", err)
		return
	}

	fmt.Print("Enter ciphertext: ")
	ciphertextHex, _ := reader.ReadString('\n')
	ciphertextHex = strings.TrimSpace(ciphertextHex)

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		fmt.Println("Invalid ciphertext:", err)
		return
	}

	sharedSecret, err := gokyber.KemDecrypt(ciphertext, privateKey, 768)
	if err != nil {
		fmt.Println("Error decrypting:", err)
		return
	}

	fmt.Printf("\nShared secret: %x\n", sharedSecret)
}

// Update the saveUsersToCSV function to include password
func saveUsersToCSV(users map[string]User) {
	file, err := os.Create("users.csv") // Changed to Create to overwrite existing file
	if err != nil {
		fmt.Println("Error opening/creating CSV:", err)
		return
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, user := range users {
		record := []string{user.Name, fmt.Sprintf("%x", user.PublicKey), user.Password}
		if err := writer.Write(record); err != nil {
			fmt.Println("Error writing record:", err)
		}
	}
	fmt.Println("User data saved to users.csv")
}

// Update the loadUsersFromCSV function to load the password field
func loadUsersFromCSV(users map[string]User) {
	file, err := os.Open("users.csv")
	if os.IsNotExist(err) {
		return
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		fmt.Println("Error reading CSV:", err)
		return
	}

	for _, record := range records {
		if len(record) < 2 {
			fmt.Println("Invalid CSV record:", record)
			continue
		}

		username := record[0]
		publicKey, err := hex.DecodeString(record[1])
		if err != nil {
			fmt.Println("Invalid public key in CSV:", err)
			continue
		}

		password := ""
		if len(record) >= 3 {
			password = record[2]
		}

		users[username] = User{Name: username, PublicKey: publicKey, Password: password}
	}
	fmt.Println("Users loaded from users.csv")
}

func userExistsInCSV(username string) bool {
	users := make(map[string]User)
	loadUsersFromCSV(users)
	_, exists := users[username]
	return exists
}
