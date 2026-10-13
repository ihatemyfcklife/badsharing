module github.com/ihatemyfcklife/badsharing/transport/webrtc

go 1.24.0

require (
	github.com/ihatemyfcklife/badsharing v1.2.0
	github.com/pion/webrtc/v4 v4.2.23
)

// Keep this optional transport working against the parent library in this
// repository. Run "go mod tidy" in this directory before the first build.
replace github.com/ihatemyfcklife/badsharing => ../..
