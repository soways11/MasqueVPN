module github.com/soways11/masquevpn

go 1.24.7

replace (
	go.uber.org/mock => github.com/uber-go/mock v0.5.2
	golang.org/x/crypto => github.com/golang/crypto v0.41.0
	golang.org/x/image => github.com/golang/image v0.20.0
	golang.org/x/mod => github.com/golang/mod v0.27.0
	golang.org/x/net => github.com/golang/net v0.43.0
	golang.org/x/sync => github.com/golang/sync v0.16.0
	golang.org/x/sys => github.com/golang/sys v0.35.0
	golang.org/x/text => github.com/golang/text v0.28.0
	golang.org/x/time => github.com/golang/time v0.12.0
	golang.org/x/tools => github.com/golang/tools v0.36.0
)

require (
	github.com/gaukas/clienthellod v0.4.2
	github.com/google/nftables v0.3.0
	github.com/jezek/xgb v1.1.1
	github.com/quic-go/qpack v0.6.0
	github.com/quic-go/quic-go v0.59.0
	github.com/refraction-networking/uquic v0.0.6
	github.com/refraction-networking/utls v1.8.2
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/crypto v0.41.0
	golang.org/x/image v0.20.0
	golang.org/x/sys v0.35.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/mdlayher/netlink v1.7.3-0.20250113171957-fbb4dce95f42 // indirect
	github.com/mdlayher/socket v0.5.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/exp v0.0.0-20240416160154-fe59bbe5cc7f // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)

replace gopkg.in/yaml.v3 => github.com/go-yaml/yaml/v3 v3.0.1

replace gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20201130134442-10cb98267c6c

replace golang.org/x/exp => github.com/golang/exp v0.0.0-20240416160154-fe59bbe5cc7f

replace golang.org/x/lint => github.com/golang/lint v0.0.0-20210508222113-6edffad5e616

replace golang.org/x/term => github.com/golang/term v0.34.0

replace golang.org/x/telemetry => github.com/golang/telemetry v0.0.0-20250807160809-1a19826ec488

replace google.golang.org/protobuf => github.com/protocolbuffers/protobuf-go v1.33.0

replace honnef.co/go/tools => github.com/dominikh/go-tools v0.1.3

replace github.com/refraction-networking/uquic => ./third_party/uquic
