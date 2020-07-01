# architecture

* class Resolver, public interface, hold private ref to dnscrypt client
* class DNSCryptClient, private interface, implements dns api methods
* receive certificate using something like `_construct`.
* drop state management using `next-state`, recreate client when certificate expired.
* class Session used to store session data, like certificate.
* class UDPSocket and TCPSocket used as low-lever transport, hide impl details here.
* class DNSCryptSocket is independent transport for DNSCryptClient, hide udp and tcp transport details.
* do not use global default resolver due to it's need explicit state management.
* leave encrypt / decrypt / verify in a module, just rename it.