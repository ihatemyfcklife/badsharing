package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/ihatemyfcklife/badsharing"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "send":
		runSend(os.Args[2:])
	case "recv":
		runRecv(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: badsharing <command> [arguments]")
	fmt.Println("Commands:")
	fmt.Println("  send  - Send a file over UDP with RLNC and AEAD encryption")
	fmt.Println("  recv  - Receive a file over UDP with Gauss-Jordan reconstruction")
}

func runSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	filePath := fs.String("file", "", "Path to the file to send (required)")
	targetAddr := fs.String("addr", "127.0.0.1:9099", "Target UDP address (IP:port)")
	passphrase := fs.String("key", "badsharing-default-secret", "Shared encryption passphrase")
	redundancy := fs.Float64("redundancy", 0.30, "Parity redundancy ratio (e.g. 0.30 = 30% parity)")
	simLoss := fs.Float64("loss", 0.0, "Simulated outbound packet drop ratio (0.0 - 0.50)")
	_ = fs.Parse(args)

	if *filePath == "" {
		fmt.Println("Error: -file is required")
		fs.Usage()
		os.Exit(1)
	}

	file, err := os.Open(*filePath)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		fmt.Printf("Error getting file stats: %v\n", err)
		os.Exit(1)
	}

	meta, err := badsharing.NewFileMetadata(fi.Name(), file)
	if err != nil {
		fmt.Printf("Error generating metadata: %v\n", err)
		os.Exit(1)
	}

	raddr, err := net.ResolveUDPAddr("udp", *targetAddr)
	if err != nil {
		fmt.Printf("Error resolving target address: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		fmt.Printf("Error connecting to UDP: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	key := badsharing.DeriveKeyFromPassphrase(*passphrase)

	cfg := badsharing.SessionConfig{
		SessionID:       meta.SessionID,
		SharedKey:       key,
		WindowSize:      32,
		RedundancyRatio: *redundancy,
	}

	sender, err := badsharing.NewSender(meta, file, cfg)
	if err != nil {
		fmt.Printf("Error initializing sender: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sending file: %s (%d bytes, %d chunks, SessionID=%x)\n",
		meta.Name, meta.Size, meta.TotalChunks, meta.SessionID)
	fmt.Printf("Target: %s | Redundancy: %.0f%% | Simulated Loss: %.0f%%\n", *targetAddr, *redundancy*100, *simLoss*100)

	// Send authenticated encrypted metadata header first (repeated 5 times for lossy links)
	encMetaBytes, err := meta.MarshalEncrypted(key)
	if err != nil {
		fmt.Printf("Error sealing metadata: %v\n", err)
		os.Exit(1)
	}

	for i := 0; i < 5; i++ {
		_, _ = conn.Write(encMetaBytes)
		time.Sleep(10 * time.Millisecond)
	}

	sentFrames := 0
	droppedFrames := 0
	startTime := time.Now()

	for {
		frame, eof, err := sender.NextFrame()
		if err != nil {
			fmt.Printf("Error reading next frame: %v\n", err)
			os.Exit(1)
		}
		if eof {
			break
		}

		sentFrames++

		// Simulated loss
		if *simLoss > 0 && rand.Float64() < *simLoss {
			droppedFrames++
			continue
		}

		if _, err := conn.Write(frame); err != nil {
			fmt.Printf("Error writing to UDP socket: %v\n", err)
			os.Exit(1)
		}

		// Pacing to prevent kernel UDP buffer overflows
		if sentFrames%32 == 0 {
			time.Sleep(100 * time.Microsecond)
		}
	}

	duration := time.Since(startTime)
	dataSent, paritySent := sender.Stats()

	fmt.Printf("\nTransmission finished in %s!\n", duration)
	fmt.Printf("Data Shards: %d | Parity Shards: %d | Dropped (simulated): %d\n",
		dataSent, paritySent, droppedFrames)
}

func runRecv(args []string) {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	outPath := fs.String("out", "", "Output destination file path (optional, defaults to source name)")
	listenAddr := fs.String("listen", ":9099", "UDP listen address (IP:port)")
	passphrase := fs.String("key", "badsharing-default-secret", "Shared encryption passphrase")
	_ = fs.Parse(args)

	laddr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		fmt.Printf("Error resolving listen address: %v\n", err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		fmt.Printf("Error listening on UDP socket: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("Listening for incoming Badsharing stream on %s...\n", *listenAddr)

	buf := make([]byte, 2048)
	var meta badsharing.FileMetadata

	key := badsharing.DeriveKeyFromPassphrase(*passphrase)

	// Step 1: Wait for metadata packet (authenticated encrypted or plaintext)
	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("Error reading UDP: %v\n", err)
			os.Exit(1)
		}

		if bytes.HasPrefix(buf[:n], badsharing.MagicEncryptedHeader[:]) {
			if err := meta.UnmarshalEncrypted(buf[:n], key); err == nil {
				fmt.Printf("Received authenticated encrypted metadata: %s (%d bytes, SHA256=%x, SessionID=%x)\n",
					meta.Name, meta.Size, meta.Checksum, meta.SessionID)
				break
			}
		} else if bytes.HasPrefix(buf[:n], badsharing.MagicHeader[:]) {
			if err := meta.UnmarshalBinary(buf[:n]); err == nil {
				fmt.Printf("Received metadata: %s (%d bytes, SHA256=%x, SessionID=%x)\n",
					meta.Name, meta.Size, meta.Checksum, meta.SessionID)
				break
			}
		}
	}

	destinationPath := *outPath
	if destinationPath == "" {
		destinationPath = "received_" + filepath.Base(filepath.Clean(meta.Name))
	}
	partPath := destinationPath + ".part"

	outFile, err := os.Create(partPath)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}

	cfg := badsharing.SessionConfig{
		SessionID:  meta.SessionID,
		SharedKey:  key,
		WindowSize: 32,
	}

	receiver, err := badsharing.NewReceiver(&meta, outFile, cfg)
	if err != nil {
		_ = outFile.Close()
		_ = os.Remove(partPath)
		fmt.Printf("Error initializing receiver: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Receiving to: %s\n", destinationPath)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Timeout after idle duration
			break
		}

		// Reset deadline on incoming packet
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))

		// Skip metadata packets
		if bytes.HasPrefix(buf[:n], badsharing.MagicHeader[:]) || bytes.HasPrefix(buf[:n], badsharing.MagicEncryptedHeader[:]) {
			continue
		}

		completed, _ := receiver.IngestFrame(buf[:n])
		if completed {
			break
		}
	}

	_ = outFile.Close()

	if err := receiver.Close(); err != nil {
		_ = os.Remove(partPath)
		fmt.Printf("Transfer verification failed: %v\n", err)
		os.Exit(1)
	}

	// Atomically finalize file
	if err := os.Rename(partPath, destinationPath); err != nil {
		fmt.Printf("Error finalizing destination file: %v\n", err)
		os.Exit(1)
	}

	rxFrames, dropFrames := receiver.Stats()
	fmt.Printf("\nFile successfully received and 100%% verified against SHA-256!\n")
	fmt.Printf("Saved to: %s\n", destinationPath)
	fmt.Printf("Frames Processed: %d | Frames Dropped: %d\n", rxFrames, dropFrames)
}
