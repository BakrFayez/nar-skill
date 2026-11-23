# Network traffic analysis

Network analysis answers a question static analysis cannot: what
does the app actually send and receive when it runs? The tools here
are a TLS-intercepting proxy (mitmproxy) and a packet analyzer
(tshark). Use them on your own apps, your own test devices, and your
own traffic only.

## Authorization boundary

Only capture traffic you are authorized to capture: your own apps,
your own devices, your own test accounts, and traffic you generated
yourself. Do not capture other people's traffic, do not capture
traffic from an app you do not own or have permission to analyze,
and do not use a capture to extract other users' credentials,
tokens, or private data. A proxy that can read TLS traffic is a
powerful tool; the boundary is what makes its use legitimate
analysis instead of interception.

This guide also does not teach certificate pinning bypass. Pinning
is covered below only as an obstacle you may observe, with what it
looks like when it happens.

## Tools and setup

Two tools do the work. mitmproxy runs the proxy and records flows.
tshark reads packet captures.

Install mitmproxy in its own virtual environment:

```bash
python3 -m venv ~/workspace/tools/mitmproxy-venv
~/workspace/tools/mitmproxy-venv/bin/pip install mitmproxy
~/workspace/tools/mitmproxy-venv/bin/mitmdump --version
```

Verified install: mitmproxy 12.3.1, Python 3.12.3, OpenSSL 4.0.3.
`mitmdump` is the command-line form of mitmproxy; it logs flows to
the console and can save them to a file. The interactive console
(`mitmproxy`) and the web UI (`mitmweb`) share the same engine and
the same CA.

tshark ships with the system Wireshark install. Verify it:

```bash
tshark --version
```

Verified: TShark (Wireshark) 4.2.2. The same install provides
`text2pcap`, `editcap`, `mergecap`, and `capinfos`.

## Proving the proxy works: loopback test

Before pointing a device at the proxy, prove the proxy captures.
Run a small local HTTP server, start mitmdump, and send a request
through the proxy:

```bash
python3 -m http.server 8899 --bind 127.0.0.1 --directory www &
~/workspace/tools/mitmproxy-venv/bin/mitmdump -p 8080 -w loopback-flows --set block_global=false &
curl -x http://127.0.0.1:8080 http://127.0.0.1:8899/hello.txt
```

Verified output from mitmdump:

```
[05:27:49.700] HTTP(S) proxy listening at *:8080.
[05:27:52.571][127.0.0.1:40090] client connect
[05:27:52.580][127.0.0.1:40090] server connect 127.0.0.1:8899
127.0.0.1:40090: GET http://127.0.0.1:8899/hello.txt HTTP/1.1
     << HTTP/1.0 200 OK 29b
```

The flow file `loopback-flows` was 1,942 bytes for this one
request and response. One environment gotcha is worth recording:
if the shell sets `no_proxy` for loopback addresses, curl bypasses
the proxy for `127.0.0.1` and the request never reaches mitmdump,
while still succeeding. Unset the variables for the test
(`env -u no_proxy -u NO_PROXY curl ...`) and confirm the flow
appears in the mitmdump log. A request that returns content proves
nothing on its own; the flow in the log is the proof.

## TLS interception and the mitmproxy CA

On first run, mitmproxy generates its own certificate authority
under `~/.mitmproxy/`. The client must trust that CA, or TLS
connections fail. Inspect the generated CA:

```bash
openssl x509 -in ~/.mitmproxy/mitmproxy-ca-cert.pem -noout -subject -issuer -dates
```

Verified: subject and issuer `CN = mitmproxy, O = mitmproxy`,
self-signed, valid for 10 years from generation. The certificate
file to install on a client is `~/.mitmproxy/mitmproxy-ca-cert.pem`
(also available as `.cer` and `.p12` in the same directory).

HTTPS interception was verified end to end against a local TLS
server: curl trusting the mitmproxy CA, through the proxy, to an
HTTPS server. mitmdump logged the decrypted request:

```
127.0.0.1:42262: GET https://127.0.0.1:8443/hello.txt HTTP/1.1
     << HTTP/1.0 200 OK 29b
```

The flow file was 3,166 bytes. Two behaviors are worth knowing.
First, mitmproxy verifies the upstream server certificate by
default: against a self-signed test server it returned `502 Bad
Gateway` with `Certificate verify failed: self-signed certificate`,
and the flow recorded the failure. The lab-only option
`--set ssl_insecure=true` makes mitmproxy accept the upstream
certificate anyway. Use it only for test servers you control.
Second, the client side and the server side are separate TLS
connections. A client that does not trust the mitmproxy CA fails
before any flow is recorded.

## Capturing from a device or emulator

This section is documented, not live-tested. No device or emulator
was available in this environment, so the procedure below was not
run against a real app. Follow it on your own test device and
record what actually happens.

1. Start mitmdump on the workstation, listening on an address the
   device can reach (the default `*:8080` listens on all
   interfaces). Save flows with `-w`.
2. On the device, set the Wi-Fi proxy to the workstation address
   and port 8080. On an emulator, start it with `-http-proxy
   <workstation-ip>:8080` instead.
3. Install the mitmproxy CA on the device (next section), then open
   the app and use the feature you want to observe.
4. Stop mitmdump with Ctrl-C. The flow file holds the capture.

Keep the capture short and targeted. A long capture mixes the
traffic you care about with background sync, update checks, and
other apps' traffic, and makes the review harder.

## CA install on a test device or emulator

Documented, not live-tested here. The shape of the procedure:

- Copy `~/.mitmproxy/mitmproxy-ca-cert.pem` (or the `.cer` form)
  to the device.
- On Android, install it from Settings under Security, then
  Certificate installation. On Android 7 and later, apps target
  API 24 or higher and do not trust user-installed CAs by default,
  so a user-installed CA alone may not make an app's TLS traffic
  visible. A test device you control can install the CA as a
  system CA, or the app under test can be a debug build that
  trusts user CAs. Both options apply to your own test devices
  and your own apps.
- On an emulator, the CA can be installed the same way, or pushed
  into the system certificate store on a writable system image.

Do not install a proxy CA on a device you do not own, and remove
the CA from a test device when the analysis is done. A trusted
proxy CA lets the proxy read that device's TLS traffic, which is
exactly why it must stay on test devices only.

## Reading flows

Replay a saved flow file without starting the proxy:

```bash
~/workspace/tools/mitmproxy-venv/bin/mitmdump -nr loopback-flows
```

Verified output:

```
127.0.0.1:40090: GET http://127.0.0.1:8899/hello.txt HTTP/1.1
     << HTTP/1.0 200 OK 29b
```

Read flows for hosts, paths, methods, and status codes first, then
open individual flows for headers and bodies. A flow proves the app
sent that request to that host at that time. It does not prove
what the server did with it, and it does not prove the app's
intent. Pair flow evidence with the static findings: a host that
appears both in `libapp.so` strings and in a capture is a stronger
finding than either alone.

## tshark pcap analysis

A pcap file is the raw packet record. tshark reads it back, filters
it, and extracts fields. Live capture was not testable in this
environment: the sandbox blocks raw sockets (`cap_set_proc() fail
return: Operation not permitted`, and `tshark -D` lists no real
interfaces). The read-back commands below were verified against a
real pcap file built with `text2pcap` from a recorded HTTP exchange
(2 packets, 363 bytes, Ethernet/IP/TCP/HTTP).

Build a pcap from a hex dump when you need a test file:

```bash
text2pcap -F pcap -4 127.0.0.1,127.0.0.1 -T 40090,8899 http-exchange.hex loopback.pcap
capinfos loopback.pcap
```

`capinfos` confirmed the file: Wireshark pcap, Ethernet
encapsulation, 2 packets, 363 bytes.

Read the capture back:

```bash
tshark -r loopback.pcap
```

Verified output:

```
    1   0.000000    127.0.0.1 → 127.0.0.1    HTTP 147 GET /hello.txt HTTP/1.1
    2   0.000001    127.0.0.1 → 127.0.0.1    HTTP 160 HTTP/1.0 200 OK
```

Extract HTTP fields as columns:

```bash
tshark -r loopback.pcap -Y http -T fields -e frame.number -e http.request.method -e http.request.uri -e http.response.code -e http.host
```

Verified output:

```
1	GET	/hello.txt		127.0.0.1:8899
2			200
```

Follow one TCP stream to reconstruct the full exchange:

```bash
tshark -r loopback.pcap -q -z follow,tcp,ascii,0
```

Verified: the follow output reproduced the request
(`GET /hello.txt HTTP/1.1`, `Host: 127.0.0.1:8899`,
`User-Agent: nar-pcap-test/1.0`) and the response
(`HTTP/1.0 200 OK`, body `hello from nar loopback test`) in full.

Summarize the protocol mix:

```bash
tshark -r loopback.pcap -q -z io,phs
```

Verified: `eth frames:2 bytes:307`, with `ip`, `tcp`, and `http`
each at 2 frames. On a real capture this hierarchy is the quick
check for what is in the file before you filter deeper.

Useful display filters for app traffic: `http` for plain HTTP,
`tls.handshake.type == 1` for TLS ClientHello packets (which show
the SNI hostname even when the body is encrypted), `dns` for name
lookups, and `ip.addr == <address>` to isolate one host. These
filters are standard tshark usage; only the commands above were
run against a file in this environment.

## Certificate pinning as an observed obstacle

Some apps pin their server certificate or public key: they accept
only a specific certificate, not any certificate the system trusts.
When that happens with a proxy CA installed, the app fails to
connect. What you observe:

- The app shows a network error, a blank screen, or a retry prompt
  for the affected feature, while the device browser on the same
  proxy loads pages fine.
- mitmdump logs a client TLS failure or a connection that ends
  during the handshake, with no HTTP flow recorded for that host.
- The failure is consistent for that app and that host, and it
  disappears when the proxy is removed.

That observation is the finding: "this app pins its certificate
for this host, so its TLS traffic was not observable through the
proxy." Record it and move on. This guide does not teach bypassing
pinning, and NAR does not provide pinning-bypass tooling. If the
traffic is needed, the legitimate routes are a debug build of your
own app, or the app's own logging on a test device you control.

## What traffic analysis cannot prove

A capture shows what happened during the capture window, on that
device, with that account, on that network. It does not prove the
app always behaves that way, and it does not prove what the app
does when the proxy is absent. Traffic that never appears may be
absent, or it may need a feature you did not trigger, a condition
you did not meet, or a network path the proxy did not see.

Encrypted traffic you cannot decrypt still yields metadata: DNS
names, TLS SNI hostnames, packet sizes, timing, and destination
addresses. Report metadata as metadata. Do not guess at encrypted
content.

## What was verified and what was not

Verified in this environment: mitmproxy 12.3.1 install and
`mitmdump --version`; HTTP capture through the proxy on loopback
with a saved and replayed flow file; HTTPS interception with the
mitmproxy CA against a local TLS server; tshark 4.2.2 read-back of
a real pcap file, including field extraction, TCP stream follow,
and protocol hierarchy.

Not tested here: live packet capture (blocked by the sandbox, no
raw socket permission); capture from a real device or emulator;
CA installation on Android; any app's real traffic. Those steps
are documented from standard procedure and marked as such above.
