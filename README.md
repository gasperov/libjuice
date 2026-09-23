# libjuice - UDP Interactive Connectivity Establishment

[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-blue.svg)](https://www.mozilla.org/en-US/MPL/2.0/)
[![Build and test](https://github.com/paullouisageneau/libjuice/actions/workflows/build.yml/badge.svg)](https://github.com/paullouisageneau/libjuice/actions/workflows/build.yml)
[![Packaging status](https://repology.org/badge/tiny-repos/libjuice.svg)](https://repology.org/project/libjuice/versions)
[![Latest packaged version](https://repology.org/badge/latest-versions/libjuice.svg)](https://repology.org/project/libjuice/versions)
[![Gitter](https://badges.gitter.im/libjuice/community.svg)](https://gitter.im/libjuice/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Discord](https://img.shields.io/discord/903257095539925006?logo=discord)](https://discord.gg/jXAP8jp3Nn)

libjuice :lemon::sweat_drops: (_JUICE is a UDP Interactive Connectivity Establishment library_) allows to open bidirectionnal User Datagram Protocol (UDP) streams with Network Address Translator (NAT) traversal.

The library is a simplified implementation of the Interactive Connectivity Establishment (ICE) protocol, client-side and server-side, written in C without dependencies for multiple platforms, including GNU/Linux, Android, FreeBSD, Apple macOS, iOS, and Microsoft Windows. The client supports only a single component over UDP per session in a standard single-gateway network topology, as this should be sufficient for the majority of use cases nowadays.

libjuice is licensed under MPL 2.0, see [LICENSE](https://github.com/paullouisageneau/libjuice/blob/master/LICENSE).

libjuice is available on [AUR](https://aur.archlinux.org/packages/libjuice-git) and [vcpkg](https://vcpkg.io/en/getting-started). Bindings are available for [Rust](https://github.com/VollmondT/juice-rs).

For a STUN/TURN server application based on libjuice, see [Violet](https://github.com/paullouisageneau/violet).

## Compatibility

The library implements a simplified full ICE agent ([RFC5245](https://www.rfc-editor.org/rfc/rfc5245.html) then [RFC8445](https://www.rfc-editor.org/rfc/rfc8445.html)) featuring:
- STUN protocol ([RFC5389](https://www.rfc-editor.org/rfc/rfc5389.html) then [RFC8489](https://www.rfc-editor.org/rfc/rfc8489.html))
- TURN relaying ([RFC5766](https://www.rfc-editor.org/rfc/rfc5766.html) then [RFC8656](https://www.rfc-editor.org/rfc/rfc8656.html))
- TURN over TCP (base TURN transport, [RFC5766](https://www.rfc-editor.org/rfc/rfc5766.html) then [RFC8656](https://www.rfc-editor.org/rfc/rfc8656.html))
- TURN over TLS (base TURN transport, [RFC5766](https://www.rfc-editor.org/rfc/rfc5766.html) then [RFC8656](https://www.rfc-editor.org/rfc/rfc8656.html)), Microsoft Windows only via SChannel, requires `USE_SCHANNEL`
- TCP candidates ([RFC6544](https://www.rfc-editor.org/rfc/rfc6544.html))
- ICE Consent freshness ([RFC7675](https://www.rfc-editor.org/rfc/rfc7675.html))
- ICE Patiently Awaiting Connectivity ([RFC 8863](https://www.rfc-editor.org/rfc/rfc8863.html))
- SDP-based interface ([RFC8839](https://www.rfc-editor.org/rfc/rfc8839.html))
- IPv4 and IPv6 dual-stack support
- Optional multiplexing on a single UDP port

The limitations compared to a fully-featured ICE agent are:
- Only UDP is supported as transport protocol between peers and other protocols are ignored. TCP and TLS are supported only as the transport to the TURN server; relayed traffic is still UDP.
- TURN over TCP and TLS are available only in the default poll concurrency mode (`JUICE_CONCURRENCY_MODE_POLL`).
- At most 3 TURN servers are used per agent, shared across UDP, TCP and TLS.
- Only one component is supported, which is sufficient for WebRTC Data Channels and multiplexed RTP+RTCP.
- Only [RFC8828](https://www.rfc-editor.org/rfc/rfc8828) mode 2 is supported (default route + all local addresses).

It also implements a lightweight STUN/TURN server ([RFC8489](https://www.rfc-editor.org/rfc/rfc8489.html) and [RFC8656](https://www.rfc-editor.org/rfc/rfc8656.html)). The server can be disabled at compile-time with the `NO_SERVER` flag.

## Dependencies

None!

Optionally, [Nettle](https://www.lysator.liu.se/~nisse/nettle/) can provide SHA1 and SHA256 algorithms instead of the internal implementation.

On Microsoft Windows, TURN over TLS uses the system SChannel library (`secur32` and `crypt32`), so no third-party TLS library is required.

## Building

### Clone repository

```bash
$ git clone https://github.com/paullouisageneau/libjuice.git
$ cd libjuice
```

### Build with CMake

The CMake library targets `libjuice` and `libjuice-static` respectively correspond to the shared and static libraries. The default target will build the library and tests. It exports the targets with namespace `LibJuice::LibJuice` and `LibJuice::LibJuiceStatic` to link the library from another CMake project.

#### POSIX-compliant operating systems (including Linux and Apple macOS)

```bash
$ cmake -B build
$ cd build
$ make -j2
```

The option `USE_NETTLE` allows to use the Nettle library instead of the internal implementation for HMAC-SHA1:
```bash
$ cmake -B build -DUSE_NETTLE=1
$ cd build
$ make -j2
```

#### Microsoft Windows with MinGW cross-compilation

```bash
$ cmake -B build -DCMAKE_TOOLCHAIN_FILE=/usr/share/mingw/toolchain-x86_64-w64-mingw32.cmake # replace with your toolchain file
$ cd build
$ make -j2
```

#### Microsoft Windows with Microsoft Visual C++

```bash
$ cmake -B build -G "NMake Makefiles"
$ cd build
$ nmake
```

The option `USE_SCHANNEL` enables TURN over TLS through SChannel (Windows only, ignored on other platforms):
```bash
$ cmake -B build -G "NMake Makefiles" -DUSE_SCHANNEL=ON
$ cd build
$ nmake
```

The option also works with MinGW cross-compilation.

### Build directly with Make (Linux only)

```bash
$ make
```

The option `USE_NETTLE` allows to use the Nettle library instead of the internal implementation for HMAC-SHA1:
```bash
$ make USE_NETTLE=1
```

## Example

See [test/connectivity.c](https://github.com/paullouisageneau/libjuice/blob/master/test/connectivity.c) for a complete local connection example.

See [test/server.c](https://github.com/paullouisageneau/libjuice/blob/master/test/server.c) for a server example.

### TURN over TCP and TLS

In addition to UDP TURN servers passed in `juice_config_t`, TCP and TLS TURN servers can be added to an agent before gathering candidates:

```c
juice_agent_t *agent = juice_create(&config); // config.concurrency_mode must be JUICE_CONCURRENCY_MODE_POLL

juice_turn_server_t turn_tcp = {
    .host = "turn.example.com",
    .port = 3478, // defaults to 3478 if 0
    .username = "user",
    .password = "pass",
};
juice_add_turn_server_tcp(agent, &turn_tcp);

// Windows only, requires the library built with USE_SCHANNEL
juice_turn_server_t turn_tls = {
    .host = "turn.example.com",
    .port = 5349, // defaults to 5349 if 0
    .username = "user",
    .password = "pass",
};
juice_add_turn_server_tls(agent, &turn_tls, false); // true skips certificate validation (e.g. self-signed)

juice_gather_candidates(agent);
```

The server certificate is validated against the system trust store and the host name. `juice_add_turn_server_tls()` returns `JUICE_ERR_FAILED` if the library was built without `USE_SCHANNEL` or on a non-Windows platform.

When UDP TURN servers are also configured, TCP and TLS allocations are started after a short delay (3 seconds) so UDP relays are preferred when available. Relayed candidates are prioritized UDP > TCP > TLS.

Once connected, `juice_get_selected_relay_transport()` returns the transport of the selected relay (`JUICE_TURN_TRANSPORT_UDP`, `JUICE_TURN_TRANSPORT_TCP` or `JUICE_TURN_TRANSPORT_TLS`), or `-1` if the selected pair is not relayed.

## Contributing

See [CONTRIBUTING.md](https://github.com/paullouisageneau/libjuice/blob/master/CONTRIBUTING.md) for contribution guidelines.

