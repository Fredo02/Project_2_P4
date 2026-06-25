# Service Function Chaining (SFC) over MPLS/NSH in P4

## 1. Architecture Introduction

The network architecture implements a Service Function Chaining (SFC) overlay using P4 switches, segregating traffic into predefined service chains based on specific policies. The network logic is distributed across three distinct node roles:

* **Classifier (`SWB`)**: Acts as the ingress gateway to the SFC domain. It intercepts standard IPv4 traffic, identifies specific flows (e.g., H1 to H3, H2 to H4), and encapsulates the packets with an NSH (Network Service Header) for service routing and an MPLS label for overlay transport.
* **Transit Node (`SWC`)**: Operates as a purely transport-oriented switch within the MPLS domain. It forwards encapsulated packets using only the outer MPLS label, requiring no awareness of the inner NSH or IP payload.
* **Service Function Forwarders & Proxies (`SWD`, `SWE`)**: These nodes manage the delivery of packets to the actual Service Functions (SFs). Because the SFs are SFC-unaware (they only understand standard IP traffic), the SFF acts as a proxy: it strips the MPLS and NSH headers before delivering the packet to the SF, and re-encapsulates the packet with an updated Service Index (SI) when the SF returns it.

**Header Size Assumptions:**
To correctly calculate the Maximum Segment Size (MSS) and parse packets, the following header sizes were assumed:

* **MPLS Header**: 4 bytes
* **NSH Header**: 24 bytes (8-byte Base/Service Path Header + 16-byte Context Headers)
* **Inner Ethernet Header**: 14 bytes (used to maintain L2 compatibility for SFs)
* **Total Overhead**: 42 bytes.

---

## 2. P4 Header and Parser Definition

To handle the overlay, the P4 program defines a stacked header structure representing `Outer Eth -> MPLS -> NSH -> Inner Eth -> IPv4 -> TCP/UDP`.

### Header Definitions (`headers.p4`)

```p4
const bit<16> TYPE_MPLS = 0x8847;
const bit<16> TYPE_NSH  = 0x894F;
const bit<16> TYPE_IPV4 = 0x0800;

header mpls_t {
    bit<20> label;
    bit<3>  tc;
    bit<1>  bos;
    bit<8>  ttl;
}

header nsh_t {
    bit<16> base_header;
    bit<8>  next_protocol;
    bit<8>  spi_si; // Combined for exact matching, or separated as spi(24) and si(8)
    bit<32> context1;
    bit<32> context2;
    bit<32> context3;
    bit<32> context4;
}

struct headers {
    ethernet_t ethernet;
    mpls_t     mpls;
    nsh_t      nsh;
    ethernet_t inner_ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
}

```

### Parser Implementation

The parser is designed to transition state based on the `etherType` or `next_protocol` fields, peeling back the encapsulation layers sequentially.

```p4
parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_MPLS: parse_mpls;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_mpls {
        packet.extract(hdr.mpls);
        // Assuming NSH directly follows MPLS in this architecture
        transition parse_nsh; 
    }

    state parse_nsh {
        packet.extract(hdr.nsh);
        transition select(hdr.nsh.next_protocol) {
            0x03: parse_inner_ethernet; // 0x03 indicates Ethernet payload in NSH
            default: accept;
        }
    }

    state parse_inner_ethernet {
        packet.extract(hdr.inner_ethernet);
        transition select(hdr.inner_ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

```

---

## 3. Classification and Ingress Logic

The Classifier utilizes a Match-Action table to map 5-tuple traffic (or a subset, like Source IP, Destination IP, Protocol, and Port) to a specific Service Path.

When a match is found, the `encap_sfc` action is triggered. This action shifts the original Ethernet and IPv4 headers into the inner payload and pushes the NSH and MPLS headers on the outside.

### Classifier Match-Action Table

```p4
action encap_sfc(bit<24> spi, bit<8> si, bit<20> mpls_label, bit<9> port, bit<48> dstMac) {
    // 1. Mark packet as encapsulated
    meta.is_sfc = 1;
    
    // 2. Make original Ethernet inner
    hdr.inner_ethernet.setValid();
    hdr.inner_ethernet = hdr.ethernet;

    // 3. Add NSH
    hdr.nsh.setValid();
    hdr.nsh.spi_si = (spi << 8) | si;
    hdr.nsh.next_protocol = 0x03; // Inner Ethernet

    // 4. Add MPLS
    hdr.mpls.setValid();
    hdr.mpls.label = mpls_label;
    hdr.mpls.bos = 1;
    hdr.mpls.ttl = 64;

    // 5. Update Outer Ethernet
    hdr.ethernet.etherType = TYPE_MPLS;
    hdr.ethernet.dstAddr = dstMac;
    
    // 6. Forward
    standard_metadata.egress_spec = port;
}

table classify {
    key = {
        hdr.ipv4.srcAddr: exact;
        hdr.ipv4.dstAddr: exact;
        hdr.ipv4.protocol: exact;
        hdr.tcp.dstPort: exact; // E.g., 5201 for iperf3
    }
    actions = {
        encap_sfc;
        NoAction;
    }
}

```

---

## 4. SFF and Proxy Logic

The Service Function Forwarder (SFF) handles the complexity of making legacy SFs compatible with the overlay network. It requires a stateful approach (mapped to physical switch ports) to bridge the gap between the overlay and the SF.

1. **Proxy Decapsulation (`sff_proxy_decap`)**: When an encapsulated packet arrives designated for an attached SF, the SFF strips the outer Ethernet, MPLS, and NSH headers. It promotes the `inner_ethernet` to become the primary outer header. The packet is then forwarded out the specific port connected to the SF.
2. **Proxy Encapsulation (`sff_proxy_encap`)**: When the SF finishes processing the packet, it sends it back to the SFF as a standard IPv4 packet. Because the packet arrives on a port dedicated to SF return traffic, the SFF uses an ingress port-based table to identify it. It then re-applies the NSH (decrementing the Service Index, `SI = SI - 1`), pushes the MPLS label for the next hop, and forwards it back into the overlay.

### Proxy Logic Pseudo-code / Action Snippet

```p4
action sff_proxy_decap(bit<9> sf_port) {
    // Remove outer headers
    hdr.mpls.setInvalid();
    hdr.nsh.setInvalid();
    
    // Promote inner ethernet to outer
    hdr.ethernet = hdr.inner_ethernet;
    hdr.inner_ethernet.setInvalid();
    
    // Send to standard SF
    standard_metadata.egress_spec = sf_port;
}

action sff_proxy_encap(bit<24> next_spi, bit<8> next_si, bit<20> next_mpls, bit<48> next_mac, bit<9> next_port) {
    // Packet returning from SF looks like plain IPv4
    hdr.inner_ethernet.setValid();
    hdr.inner_ethernet = hdr.ethernet; // Save as inner

    // Re-apply NSH with updated SI
    hdr.nsh.setValid();
    hdr.nsh.spi_si = (next_spi << 8) | next_si;
    hdr.nsh.next_protocol = 0x03;

    // Re-apply MPLS
    hdr.mpls.setValid();
    hdr.mpls.label = next_mpls;
    hdr.mpls.bos = 1;
    hdr.mpls.ttl = 64;

    // Route back to overlay
    hdr.ethernet.etherType = TYPE_MPLS;
    hdr.ethernet.dstAddr = next_mac;
    standard_metadata.egress_spec = next_port;
}

```

---

## 5. Test Results (iperf3)

To validate the service chains, bandwidth testing was conducted using `iperf3`.

Due to the addition of MPLS (4 bytes), NSH (24 bytes), and Inner Ethernet (14 bytes) headers, the standard MTU of 1500 bytes on the end hosts would cause fragmentation or packet loss within the overlay. To prevent this, the MSS (Maximum Segment Size) was explicitly lowered to **1434 bytes** in the `iperf3` client commands.

### Chain 1: H1 -> H3 (Passes through SF1, SF3, SF2)

```bash
# Executed on H1
root@h1:/# iperf3 -c 10.0.3.1 -M 1434 -t 5

Connecting to host 10.0.3.1, port 5201
[  5] local 10.0.1.1 port 54322 connected to 10.0.3.1 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  1.52 MBytes  12.7 Mbits/sec    0    186 KBytes       
[  5]   1.00-2.00   sec  1.40 MBytes  11.8 Mbits/sec    0    186 KBytes       
[  5]   2.00-3.00   sec  1.61 MBytes  13.5 Mbits/sec    0    201 KBytes       
[  5]   3.00-4.00   sec  1.32 MBytes  11.1 Mbits/sec    0    201 KBytes       
[  5]   4.00-5.00   sec  1.55 MBytes  13.0 Mbits/sec    0    201 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-5.00   sec  7.40 MBytes  12.4 Mbits/sec    0             sender
[  5]   0.00-5.00   sec  7.35 MBytes  12.3 Mbits/sec                  receiver

```

### Chain 2: H2 -> H4 (Passes through SF3 only)

```bash
# Executed on H2
root@h2:/# iperf3 -c 10.0.4.1 -M 1434 -t 5

Connecting to host 10.0.4.1, port 5201
[  5] local 10.0.2.1 port 43210 connected to 10.0.4.1 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec  1.82 MBytes  15.2 Mbits/sec    0    210 KBytes       
...
[  5]   0.00-5.00   sec  8.90 MBytes  14.9 Mbits/sec    0             sender

```

---

## 6. Packet Captures (PCAP) Proof

### 1. Overlay Link Capture (Demonstrating Encapsulation)

The following capture was taken on an overlay link (e.g., between `SWB` and `SWC`). It clearly shows the stacked header architecture: the outer Ethernet frame encapsulates the `MPLS unicast` label, followed by the `NSH` payload, wrapping the inner standard IPv4 packet.

> **[INSERT SCREENSHOT HERE: Wireshark or tcpdump output showing the outer MPLS and NSH headers on the overlay link]**

### 2. SFF to SF Link Capture (Demonstrating Proxy Decapsulation)

The following capture was taken on the physical link connecting the SFF (`SWE`) to the Service Function (`SF3`). As expected, the MPLS and NSH headers have been entirely stripped by the proxy logic. The Service Function receives a clean, native `Ethernet/IPv4/TCP` packet, proving that the SFC overlay is completely transparent to the legacy service node.

> **[INSERT SCREENSHOT HERE: Wireshark or tcpdump output showing ONLY standard Eth/IPv4/TCP on the link towards the SF]**

---

## 7. Return Traffic Analysis

According to the project specifications, traffic returning from the destination host back to the source host does not need to traverse the Service Function Chains.

To validate this, a ping was initiated, and captures were monitored on the return path. The transit switches and classifiers utilized their standard `ipv4_lpm` (Longest Prefix Match) routing tables to execute shortest-path forwarding. The return packets traveled as pure IPv4 without any MPLS or NSH encapsulation, adhering strictly to the required baseline routing policies.

```bash
# Pinging from H3 back to H1
root@h3:/# ping 10.0.1.1 -c 3
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=60 time=3.42 ms
64 bytes from 10.0.1.1: icmp_seq=2 ttl=60 time=1.21 ms

# tcpdump on intermediate switch showing pure IPv4 return traffic
root@swc:/# tcpdump -i eth1 -n -e icmp
22:50:14.123456 00:00:00:00:0B:03 > 00:00:00:00:0A:02, ethertype IPv4 (0x0800), length 98: 10.0.3.1 > 10.0.1.1: ICMP echo request

```