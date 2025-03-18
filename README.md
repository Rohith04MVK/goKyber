# goKyber: A High-Performance and Practical Post-Quantum Encryption Framework

<p align="center"> <img src="./docs/assests/images/logo.jpeg" height=400></p>

**goKyber** is an uncomplicated and, optimally, tuned encryption library designed to make post-quantum cryptographic algorithms, specifically the CRYSTALS-Kyber key-encapsulation mechanism (KEM), both attainable and applicable. It balances simplicity with good performance to lower the barriers associated with adopting lattice-based encryption methodologies. Whether investigating secure communications or teaching fundamental cryptographic principles, goKyber aims to provide a friendly, instructive, and powerful toolkit.

## Features
- **High-Performance Post-Quantum Encryption**: goKyber delivers cutting-edge post-quantum encryption using the CRYSTALS-Kyber key-encapsulation mechanism (KEM), optimized for speed and practicality.

- **Simplicity and Practicality**: Designed with clarity and usability in mind, goKyber lowers the barriers to adopting lattice-based encryption, making advanced security accessible to developers and educators alike.

- **Learn and Innovate**: Whether you're building secure systems or teaching cryptographic principles, goKyber provides an instructive and powerful platform for exploring the potential of post-quantum security.

## Installation
To install goKyber, use the following Go command:

```sh
go get github.com/Rohith04MVK/goKyber
```

## Usage
**Example: Basic Key Generation and Encryption**

```go
package main

import (
    "fmt"

    gokyber "github.com/Rohith04MVK/goKyber/goKyber"
)

func main() {
    // Generate a Kyber-768 key pair
    privateKey, publicKey, err := gokyber.KemKeypair(768)
    if err != nil {
        fmt.Println("Error generating key pair:", err)
        return
    }

    // Encrypt a message using the public key
    ciphertext, sharedSecret, err := gokyber.KemEncrypt(publicKey, 768)
    if err != nil {
        fmt.Println("Error encrypting message:", err)
        return
    }

    // Decrypt the ciphertext using the private key
    decryptedSecret, err := gokyber.KemDecrypt(ciphertext, privateKey, 768)
    if err != nil {
        fmt.Println("Error decrypting message:", err)
        return
    }

    // Verify that the shared secrets match
    if string(sharedSecret) == string(decryptedSecret) {
        fmt.Println("Shared secrets match! Secure communication established.")
    } else {
        fmt.Println("Shared secrets do not match! Something went wrong.")
    }
}
```

## Documentation
For more detailed documentation, including API references and advanced usage, please refer to the docs.

## Contributing
We welcome contributions to goKyber! If you have any ideas, suggestions, or bug reports, please open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

## Acknowledgements
goKyber is inspired by the CRYSTALS-Kyber project and aims to provide a practical implementation of its key-encapsulation mechanism in Go.

<p align="center">Made with 💜 by the goKyber Team</p>

