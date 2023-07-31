module codeberg.org/derat/nitter-rss-proxy

go 1.14

require (
	github.com/fastly/compute-sdk-go v0.1.6
	github.com/gorilla/feeds v1.1.1
	github.com/kr/pretty v0.3.0 // indirect
	github.com/mmcdole/gofeed v1.1.1
	golang.org/x/net v0.0.0-20220909164309-bea034e7d591 // indirect
)

// Until https://github.com/fastly/compute-sdk-go/pull/64 is merged and released
replace github.com/fastly/compute-sdk-go => ../compute-sdk-go
