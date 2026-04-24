# IPv& router advertisement daemon

This is a very simple daemon to avertise routes from the (Linux) router to the local network. Configuration
is trivial as it only needs interface name and the delegated IPv6 prefix which must be at least /64.
Advertisements use it as hardcoded value. The DNS servers are also hardcoded to Google's DNS servers.

This application can be ran basically in any Linux system. Other operating systems should equally work.

## Building

Tested and built with Go 1.26.

```
go build
```
