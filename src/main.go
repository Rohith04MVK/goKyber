package main

import (
        "bufio"
        "encoding/csv"
        "encoding/hex"
        "fmt"
        "os"
        "path/filepath"
        "strings"

        gokyber "github.com/Rohith04MVK/goKyber/goKyber"
)

type User struct {
        Name      string
        PublicKey []byte
}

func main() {
        users := make(map[string]User)
        reader := bufio.NewReader(os.Stdin)

        os.Mkdir("private_keys", 0700)
        loadUsersFromCSV(users)

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

func createUser(users map[string]User, reader *bufio.Reader) {
        fmt.Print("Enter username: ")
        username, _ := reader.ReadString('\n')
        username = strings.TrimSpace(username)

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

        users[username] = User{Name: username, PublicKey: publicKey}

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

func saveUsersToCSV(users map[string]User) {
        file, err := os.OpenFile("users.csv", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                fmt.Println("Error opening/creating CSV:", err)
                return
        }
        defer file.Close()

        writer := csv.NewWriter(file)
        defer writer.Flush()

        for _, user := range users {
                if !userExistsInCSV(user.Name) {
                        record := []string{user.Name, fmt.Sprintf("%x", user.PublicKey)}
                        if err := writer.Write(record); err != nil {
                                fmt.Println("Error writing record:", err)
                        }
                }
        }
        fmt.Println("User data saved to users.csv")
}

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
                if len(record) != 2 {
                        fmt.Println("Invalid CSV record:", record)
                        continue
                }
                username := record[0]
                publicKey, err := hex.DecodeString(record[1])
                if err != nil {
                        fmt.Println("Invalid public key in CSV:", err)
                        continue
                }
                users[username] = User{Name: username, PublicKey: publicKey}
        }
        fmt.Println("Users loaded from users.csv")
}

func userExistsInCSV(username string) bool {
        users := make(map[string]User)
        loadUsersFromCSV(users)
        _, exists := users[username]
        return exists
}
