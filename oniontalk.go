package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/awnumar/memguard"
	"golang.org/x/net/proxy"
)

const (
	defaultPort = "8001"
	torProxy    = "socks5://127.0.0.1:9050"
)

var (
	clientConnected = false
	clientMutex     sync.Mutex
)

func main() {
	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	sendMode := flag.Bool("s", false, "Run as client (send mode, requires onion address)")
	helpMode := flag.Bool("h", false, "Show help")
	flag.Parse()

	if *helpMode {
		printHelp()
		os.Exit(0)
	}

	args := flag.Args()

	if *sendMode {
		// Client mode (send)
		if len(args) < 1 {
			fmt.Println("Error: Onion address required for client mode")
			fmt.Println()
			printHelp()
			os.Exit(1)
		}
		serverURL := args[0]
		runClient(serverURL)
	} else {
		// Server mode (listen) - no flags needed
		if len(args) > 0 {
			fmt.Println("Error: Unexpected arguments for server mode")
			fmt.Println()
			printHelp()
			os.Exit(1)
		}
		runServer()
	}
}

func printHelp() {
	fmt.Println("OnionTalk - Secure talk sessions over Tor")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  Listener mode:")
	fmt.Printf("    %s\n", os.Args[0])
	fmt.Println()
	fmt.Println("  Send mode:")
	fmt.Printf("    %s -s <onion-address>\n", os.Args[0])
	fmt.Println()
	fmt.Println("Talk Commands:")
	fmt.Println("  .MULTI  - Start multi-line input")
	fmt.Println("  .END    - Finish multi-line input")
	fmt.Println("  .QUIT   - Exit the program")
}

func runServer() {
	listener, err := net.Listen("tcp", "127.0.0.1:"+defaultPort)
	if err != nil {
		log.Fatalf("Error starting the server: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Printf("Error closing listener: %v", err)
		}
	}()

	fmt.Printf("Listening...\n")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Error accepting connection: %v\n", err)
			continue
		}

		clientMutex.Lock()
		if clientConnected {
			clientMutex.Unlock()
			fmt.Println("Connection attempt rejected: Line Busy.")
			handleBusyConnection(conn)
			continue
		}
		clientConnected = true
		clientMutex.Unlock()

		fmt.Println("Client connected.")
		go handleConnection(conn)
	}
}

func handleBusyConnection(conn net.Conn) {
	_, _ = conn.Write([]byte("Line Busy\n"))
	_ = conn.Close()
}

func runClient(serverURL string) {
	// Add port if not specified - only port 8001 is allowed
	if _, port, err := net.SplitHostPort(serverURL); err != nil {
		// No port specified, add default port
		serverURL = net.JoinHostPort(serverURL, defaultPort)
	} else if port != defaultPort {
		fmt.Printf("Error: Only port %s is allowed. Use: program -s %s\n", defaultPort, serverURL[:len(serverURL)-len(port)-1])
		os.Exit(1)
	}

	torProxyUrl, err := url.Parse(torProxy)
	if err != nil {
		fmt.Println("Invalid Tor proxy URL:", err)
		return
	}

	dialer, err := proxy.FromURL(torProxyUrl, proxy.Direct)
	if err != nil {
		fmt.Println("Error creating proxy dialer:", err)
		return
	}

	conn, err := dialer.Dial("tcp", serverURL)
	if err != nil {
		fmt.Println("Error connecting to the server:", err)
		return
	}
	defer func() { _ = conn.Close() }()

	fmt.Println("Connected to the server.")
	performKeyExchange(conn, false)
}

func handleConnection(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		clientMutex.Lock()
		clientConnected = false
		clientMutex.Unlock()
		fmt.Println("Client disconnected.")
	}()

	performKeyExchange(conn, true)
}

func performKeyExchange(conn net.Conn, isServer bool) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Printf("Error generating private key: %v", err)
		return
	}

	privateKeyBuffer := memguard.NewBufferFromBytes(privateKey.Bytes())
	defer privateKeyBuffer.Destroy()

	publicKey := privateKey.PublicKey()

	// Server receives client's public key first, client sends first
	if isServer {
		clientPublicKeyBytes := make([]byte, 32)
		_, err = io.ReadFull(conn, clientPublicKeyBytes)
		if err != nil {
			log.Printf("Error receiving the client's public key: %v", err)
			return
		}

		clientPublicKey, err := curve.NewPublicKey(clientPublicKeyBytes)
		if err != nil {
			log.Printf("Error parsing the client's public key: %v", err)
			return
		}

		// Send server's public key
		publicKeyBytes := publicKey.Bytes()
		if _, err := conn.Write(publicKeyBytes); err != nil {
			log.Printf("Error sending public key: %v", err)
			return
		}

		sharedSecret, err := privateKey.ECDH(clientPublicKey)
		if err != nil {
			log.Printf("Error calculating the shared secret: %v", err)
			return
		}

		startEncryptedCommunication(conn, sharedSecret, isServer)
	} else {
		// Client sends its public key first
		publicKeyBytes := publicKey.Bytes()
		if _, err := conn.Write(publicKeyBytes); err != nil {
			fmt.Println("Error sending client's public key:", err)
			return
		}

		// Receive server's public key
		serverPublicKeyBytes := make([]byte, 32)
		_, err = io.ReadFull(conn, serverPublicKeyBytes)
		if err != nil {
			fmt.Println("Error receiving the server's public key - line busy")
			return
		}

		serverPublicKey, err := curve.NewPublicKey(serverPublicKeyBytes)
		if err != nil {
			fmt.Println("Error parsing the server's public key:", err)
			return
		}

		sharedSecret, err := privateKey.ECDH(serverPublicKey)
		if err != nil {
			fmt.Println("Error calculating the shared secret:", err)
			return
		}

		startEncryptedCommunication(conn, sharedSecret, isServer)
	}
}

func startEncryptedCommunication(conn net.Conn, sharedSecret []byte, isServer bool) {
	sharedSecretBuffer := memguard.NewBufferFromBytes(sharedSecret)
	defer sharedSecretBuffer.Destroy()

	c2s, s2c, err := deriveDirectionalKeys(sharedSecret)
	if err != nil {
		if isServer {
			log.Printf("Error deriving keys: %v", err)
		} else {
			fmt.Println("Error deriving keys:", err)
		}
		return
	}

	// Key-Separation: je nach Rolle send/recv unterschiedlich
	var sendKey, recvKey []byte
	if isServer {
		recvKey = c2s
		sendKey = s2c
	} else {
		sendKey = c2s
		recvKey = s2c
	}

	sendBlock, err := aes.NewCipher(sendKey)
	if err != nil {
		if isServer {
			log.Printf("Error initializing AES (send): %v", err)
		} else {
			fmt.Println("Error initializing AES (send):", err)
		}
		return
	}

	recvBlock, err := aes.NewCipher(recvKey)
	if err != nil {
		if isServer {
			log.Printf("Error initializing AES (recv): %v", err)
		} else {
			fmt.Println("Error initializing AES (recv):", err)
		}
		return
	}

	gcmSend, err := cipher.NewGCM(sendBlock)
	if err != nil {
		if isServer {
			log.Printf("Error initializing GCM (send): %v", err)
		} else {
			fmt.Println("Error initializing GCM (send):", err)
		}
		return
	}

	gcmRecv, err := cipher.NewGCM(recvBlock)
	if err != nil {
		if isServer {
			log.Printf("Error initializing GCM (recv): %v", err)
		} else {
			fmt.Println("Error initializing GCM (recv):", err)
		}
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)

	go receiveMessages(ctx, cancel, conn, gcmRecv, &wg, isServer)
	go sendMessages(ctx, cancel, conn, gcmSend, &wg, isServer)

	wg.Wait()

	// Best-effort close (unblocks any remaining reads/writes)
	_ = conn.Close()

}

func receiveMessages(ctx context.Context, cancel context.CancelFunc, conn net.Conn, gcm cipher.AEAD, wg *sync.WaitGroup, isServer bool) {
	defer wg.Done()

	firstMessage := true

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		payload, err := readFrame(conn)
		if err != nil {
			// Wenn Shutdown läuft, ist das erwartbar
			select {
			case <-ctx.Done():
				return
			default:
			}

			if isServer {
				fmt.Printf("Error reading frame: %v\n", err)
			} else {
				fmt.Println("Error reading frame:", err)
			}
			cancel()
			_ = conn.Close()
			return
		}

		if len(payload) < nonceSize {
			if isServer {
				fmt.Printf("Invalid frame (too short): %d\n", len(payload))
			} else {
				fmt.Println("Invalid frame (too short):", len(payload))
			}
			cancel()
			_ = conn.Close()
			return
		}

		nonce := payload[:nonceSize]
		ciphertext := payload[nonceSize:]

		decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			if isServer {
				fmt.Printf("Error decrypting message: %v\n", err)
			} else {
				fmt.Println("Error decrypting message:", err)
			}
			cancel()
			_ = conn.Close()
			return
		}

		if string(decrypted) == ".QUIT" {
			if isServer {
				clientMutex.Lock()
				clientConnected = false
				clientMutex.Unlock()
			}
			cancel()
			_ = conn.Close()
			return
		}

		if !firstMessage {
			fmt.Println()
		} else {
			firstMessage = false
		}

		fmt.Println(string(decrypted))
	}
}

// Helper function
func sendEncrypted(conn net.Conn, gcm cipher.AEAD, msg string) error {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(msg), nil)
	payload := append(nonce, ciphertext...)

	if err := writeFrame(conn, payload); err != nil {
		return fmt.Errorf("writeFrame: %w", err)
	}
	return nil
}

func sendMessages(ctx context.Context, cancel context.CancelFunc, conn net.Conn, gcm cipher.AEAD, wg *sync.WaitGroup, isServer bool) {
	defer wg.Done()
	reader := bufio.NewReader(os.Stdin)

	// Ctrl+C handler
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	defer signal.Stop(c)

	go func() {
		<-c
		_ = sendEncrypted(conn, gcm, ".QUIT")

		if isServer {
			clientMutex.Lock()
			clientConnected = false
			clientMutex.Unlock()
		}

		cancel()
		_ = conn.Close()
	}()

	for {
		// Stop if someone canceled the session
		select {
		case <-ctx.Done():
			return
		default:
		}

		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				// Ctrl+D pressed
				_ = sendEncrypted(conn, gcm, ".QUIT")
				cancel()
				_ = conn.Close()
				return
			}
			continue
		}

		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		if input == ".QUIT" {
			_ = sendEncrypted(conn, gcm, ".QUIT")

			if isServer {
				clientMutex.Lock()
				clientConnected = false
				clientMutex.Unlock()
			}

			cancel()
			_ = conn.Close()
			return
		}

		if input == ".MULTI" {
			var lines []string

			for {
				// Respect cancellation while in multi mode too
				select {
				case <-ctx.Done():
					return
				default:
				}

				line, err := reader.ReadString('\n')
				if err != nil {
					if err == io.EOF {
						_ = sendEncrypted(conn, gcm, ".QUIT")
						cancel()
						_ = conn.Close()
						return
					}
					break
				}

				line = strings.TrimSpace(line)

				if line == ".END" {
					break
				}

				if line == ".QUIT" {
					_ = sendEncrypted(conn, gcm, ".QUIT")
					cancel()
					_ = conn.Close()
					return
				}

				lines = append(lines, line)
			}

			if len(lines) > 0 {
				message := strings.Join(lines, "\n")
				if err := sendEncrypted(conn, gcm, message); err != nil {
					if isServer {
						fmt.Printf("Error sending message: %v\n", err)
					} else {
						fmt.Println("Error sending message:", err)
					}
					cancel()
					_ = conn.Close()
					return
				}
			}
			continue
		}

		// Normal single-line message
		if err := sendEncrypted(conn, gcm, input); err != nil {
			if isServer {
				fmt.Printf("Error sending message: %v\n", err)
			} else {
				fmt.Println("Error sending message:", err)
			}
			cancel()
			_ = conn.Close()
			return
		}
	}
}
