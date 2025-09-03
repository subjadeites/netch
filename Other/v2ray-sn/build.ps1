Set-Location (Split-Path $MyInvocation.MyCommand.Path -Parent)

git clone https://github.com/SagerNet/v2ray-core.git -b 'v5.0.3' src
if ( -Not $? ) {
    exit $lastExitCode
}
Set-Location src

# Add SSR and Simple-Obfs plugins
Copy-Item '..\ssr.go' '.\proxy\shadowsocks\plugin\self\ssr.go'
Copy-Item '..\obfs.go' '.\proxy\shadowsocks\plugin\self\obfs.go'

# Enable ReadV (Use old ReadV code)
Remove-Item '.\common\buf\io.go'
Remove-Item '.\common\buf\readv_reader.go'
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SagerNet/v2ray-core/2711fd1/common/buf/io.go' -OutFile '.\common\buf\io.go'
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/SagerNet/v2ray-core/2711fd1/common/buf/readv_reader.go' -OutFile '.\common\buf\readv_reader.go'

# Patch core for quic-go v0.31 API changes
git apply '..\quic-conn.patch'

$Env:CGO_ENABLED='0'
$Env:GOROOT_FINAL='/usr'

$Env:GOOS='windows'
$Env:GOARCH='amd64'
go mod download
go get github.com/lucas-clemente/quic-go@v0.31.0
go get github.com/Dreamacro/clash/transport/simple-obfs@v1.8.0
go get github.com/Dreamacro/clash/transport/ssr/obfs@v1.8.0
go get github.com/Dreamacro/clash/transport/ssr/protocol@v1.8.0
go mod tidy
go build -a -trimpath -asmflags '-s -w' -ldflags '-s -w -buildid=' -o '..\..\release\v2ray-sn.exe' '.\main'
exit $lastExitCode
