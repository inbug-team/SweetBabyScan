GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o SbScanMacAmd64
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o SbScanMacArm64