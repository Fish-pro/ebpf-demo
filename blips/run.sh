rm -rf *.o bpf_*.go
go generate
go build
./blips
