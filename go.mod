module github.com/ihatemyfcklife/badsharing

go 1.24.0

replace (
	github.com/ihatemyfcklife/badcrypt => ../crypt-rlnc
	github.com/ihatemyfcklife/badrlnc => ../go-rlnc
)

require (
	github.com/ihatemyfcklife/badcrypt v0.0.0-00010101000000-000000000000
	github.com/ihatemyfcklife/badrlnc v0.0.0-00010101000000-000000000000
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	golang.org/x/crypto v0.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)
