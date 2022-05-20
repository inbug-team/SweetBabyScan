GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o SbScanLinuxAmd64
GOOS=linux GOARCH=386 go build -ldflags="-s -w" -trimpath -o SbScanLinux386
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o SbScanAmd64.exe
GOOS=windows GOARCH=386 go build -ldflags="-s -w" -trimpath -o SbScan386.exe