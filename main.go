package main

import (
	"net"
	"fmt"
	"syscall"
	"time"
	"os"
	"io"
)

// use socket directly https://gist.github.com/jbenet/5c191d698fe9ec58c49d
// get original destination https://github.com/ryanchapman/go-any-proxy

const SO_ORIGINAL_DST = 80

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:2515")
	if err != nil {
		panic(err)
	}
	leftConn, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	leftConn, dst, dport := getOriginalDestination(leftConn)
	fd, err := newSocket()
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)
	netAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%v", dst, dport))
	if err != nil {
		panic(err)
	}
	rsa := NetAddrToSockaddr(netAddr)
	if err = connect(fd, rsa, time.Time{}); err != nil {
		fmt.Printf("connect failed: %s\n", err)
		return
	}
	f := os.NewFile(uintptr(fd), "right connection")
	rightConn, err := net.FileConn(f)
	if err != nil {
		panic(f)
	}
	defer rightConn.Close()
	go io.Copy(leftConn, rightConn)
	go io.Copy(rightConn, leftConn)
	time.Sleep(time.Minute)
}

func getOriginalDestination(leftConn net.Conn) (net.Conn, string, uint16) {
	tcpConn := leftConn.(*net.TCPConn)
	// connection => file, will make a copy
	tcpConnFile, err := tcpConn.File()
	if err != nil {
		panic(err)
	} else {
		tcpConn.Close()
	}
	addr, err :=  syscall.GetsockoptIPv6Mreq(int(tcpConnFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		panic(err)
	}
	// file => connection
	leftConn, err = net.FileConn(tcpConnFile)
	if err != nil {
		panic(err)
	}
	dst := itod(uint(addr.Multiaddr[4])) + "." +
		itod(uint(addr.Multiaddr[5])) + "." +
		itod(uint(addr.Multiaddr[6])) + "." +
		itod(uint(addr.Multiaddr[7]))
	dport := uint16(addr.Multiaddr[2]) << 8 + uint16(addr.Multiaddr[3])
	return leftConn, dst, dport
}

// from pkg/net/parse.go
// Convert i to decimal string.
func itod(i uint) string {
	if i == 0 {
		return "0"
	}

	// Assemble decimal in reverse order.
	var b [32]byte
	bp := len(b)
	for ; i > 0; i /= 10 {
		bp--
		b[bp] = byte(i%10) + '0'
	}

	return string(b[bp:])
}

func newSocket() (fd int, err error) {
	syscall.ForkLock.RLock()
	fd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err == nil {
		syscall.CloseOnExec(fd)
	}
	syscall.ForkLock.RUnlock()

	if err != nil {
		return -1, err
	}

	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, 2515); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	return fd, err
}

type timeoutError struct{}
func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
var errTimeout = &timeoutError{}

func FD_SET(fd uintptr, p *syscall.FdSet) {
	n, k := fd/32, fd%32
	p.Bits[n] |= (1 << uint32(k))
}

// this is close to the connect() function inside stdlib/net
func connect(fd int, ra syscall.Sockaddr, deadline time.Time) error {
	switch err := syscall.Connect(fd, ra); err {
	case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
	case nil, syscall.EISCONN:
		if !deadline.IsZero() && deadline.Before(time.Now()) {
			return errTimeout
		}
		return nil
	default:
		return err
	}

	var err error
	var to syscall.Timeval
	var toptr *syscall.Timeval
	var pw syscall.FdSet
	FD_SET(uintptr(fd), &pw)
	for {
		// wait until the fd is ready to read or write.
		if !deadline.IsZero() {
			to = syscall.NsecToTimeval(deadline.Sub(time.Now()).Nanoseconds())
			toptr = &to
		}

		// wait until the fd is ready to write. we can't use:
		//   if err := fd.pd.WaitWrite(); err != nil {
		//   	 return err
		//   }
		// so we use select instead.
		if _, err = Select(fd+1, nil, &pw, nil, toptr); err != nil {
			fmt.Println(err)
			return err
		}

		var nerr int
		nerr, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err != nil {
			return err
		}
		switch err = syscall.Errno(nerr); err {
		case syscall.EINPROGRESS, syscall.EALREADY, syscall.EINTR:
			continue
		case syscall.Errno(0), syscall.EISCONN:
			if !deadline.IsZero() && deadline.Before(time.Now()) {
				return errTimeout
			}
			return nil
		default:
			return err
		}
	}
}

func Select(nfd int, r *syscall.FdSet, w *syscall.FdSet, e *syscall.FdSet, timeout *syscall.Timeval) (n int, err error) {
	return syscall.Select(nfd, r, w, e, timeout)
}

// NetAddrToSockaddr converts a net.Addr to a syscall.Sockaddr.
// Returns nil if the input is invalid or conversion is not possible.
func NetAddrToSockaddr(addr net.Addr) syscall.Sockaddr {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return TCPAddrToSockaddr(addr)
	default:
		return nil
	}
}

// TCPAddrToSockaddr converts a net.TCPAddr to a syscall.Sockaddr.
// Returns nil if conversion fails.
func TCPAddrToSockaddr(addr *net.TCPAddr) syscall.Sockaddr {
	sa := IPAndZoneToSockaddr(addr.IP, addr.Zone)
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		sa.Port = addr.Port
		return sa
	case *syscall.SockaddrInet6:
		sa.Port = addr.Port
		return sa
	default:
		return nil
	}
}

// IPAndZoneToSockaddr converts a net.IP (with optional IPv6 Zone) to a syscall.Sockaddr
// Returns nil if conversion fails.
func IPAndZoneToSockaddr(ip net.IP, zone string) syscall.Sockaddr {
	switch {
	case len(ip) < net.IPv4len: // default to IPv4
		buf := [4]byte{0, 0, 0, 0}
		return &syscall.SockaddrInet4{Addr: buf}

	case ip.To4() != nil:
		var buf [4]byte
		copy(buf[:], ip[12:16]) // last 4 bytes
		return &syscall.SockaddrInet4{Addr: buf}

	}
	panic("should be unreachable")
}

