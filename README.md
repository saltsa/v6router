# IPv& router advertisement daemon

This is very simple daemon to avertise routes from the (Linux) router to the local network. Configuration
is very simple as it only needs interface name and the delegate IPv6 prefix. It defaults to advertise only 
/64 prefix. The DNS servers are also advertised and Google's DNS is used.

This application can be ran basically in any Linux system, as well as others.

## Building

Tested and built with Go 1.26.

```
go build
```
