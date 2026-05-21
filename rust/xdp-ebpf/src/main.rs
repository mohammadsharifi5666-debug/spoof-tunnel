#![no_std]
#![no_main]
#![feature(asm_experimental_arch)]

//! XDP program for high-performance spoofed packet receive & payload extraction.
//!
//! Runs at NIC driver level (XDP hook) before sk_buff allocation.
//! Uses bpf_xdp_load_bytes() for payload copy to avoid BPF verifier issues
//! with variable-offset packet pointer access.

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
};

use core::mem;

// ── Fixed offsets (constants for BPF verifier) ──
const ETH_HDR_LEN: usize = 14;
const IP_HDR_LEN: usize = 20;
const TCP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;
const ICMP_HDR_LEN: usize = 8;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

const ETHERTYPE_IPV4_BE: u16 = 0x0800u16.to_be();

/// Configuration entry stored in BPF HashMap.
#[repr(C)]
pub struct XdpConfig {
    pub peer_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: u8,
}

/// Packet metadata header prepended to payload in the ring buffer.
#[repr(C)]
pub struct PktMeta {
    pub src_ip: u32,
    pub src_port: u16,
    pub payload_len: u16,
}

#[map]
static CONFIG: HashMap<u32, XdpConfig> = HashMap::with_max_entries(1, 0);

#[map]
static PAYLOADS: RingBuf = RingBuf::with_byte_size(16 * 1024 * 1024, 0);

#[map]
static PKT_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1, 0);

#[xdp]
pub fn spoof_xdp_recv(ctx: XdpContext) -> u32 {
    match try_process(&ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_process(ctx: &XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // ── 1. Ethernet header (14 bytes) ──
    if data + ETH_HDR_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let ether_type = unsafe { *(data as *const u16).add(6) };
    if ether_type != ETHERTYPE_IPV4_BE {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── 2. IPv4 header (fixed 20 bytes) ──
    if data + ETH_HDR_LEN + IP_HDR_LEN > data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip_base = data + ETH_HDR_LEN;
    let src_ip = unsafe { *((ip_base + 12) as *const u32) };
    let ip_proto = unsafe { *((ip_base + 9) as *const u8) };

    // ── 3. Load config ──
    let key: u32 = 0;
    let cfg = match unsafe { CONFIG.get(&key) } {
        Some(c) => c,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // ── 4. Filter by protocol ──
    if cfg.protocol != 0 && ip_proto != cfg.protocol {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── 5. Filter by peer spoof IP ──
    if cfg.peer_ip != 0 && src_ip != cfg.peer_ip {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── 6. Parse transport header using FIXED offsets ──
    let transport_base = data + ETH_HDR_LEN + IP_HDR_LEN;

    let (src_port, payload_offset): (u16, u32) = match ip_proto {
        PROTO_TCP => {
            if data + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            let dst_port = u16::from_be(unsafe { *((transport_base + 2) as *const u16) });
            if cfg.dst_port != 0 && dst_port != cfg.dst_port {
                return Ok(xdp_action::XDP_PASS);
            }
            let sp = u16::from_be(unsafe { *((transport_base) as *const u16) });
            (sp, (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN) as u32)
        }
        PROTO_UDP => {
            if data + ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            let dst_port = u16::from_be(unsafe { *((transport_base + 2) as *const u16) });
            if cfg.dst_port != 0 && dst_port != cfg.dst_port {
                return Ok(xdp_action::XDP_PASS);
            }
            let sp = u16::from_be(unsafe { *((transport_base) as *const u16) });
            (sp, (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN) as u32)
        }
        PROTO_ICMP => {
            if data + ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN > data_end {
                return Ok(xdp_action::XDP_PASS);
            }
            (0u16, (ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN) as u32)
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    // ── 7. Calculate payload length ──
    if data + (payload_offset as usize) >= data_end {
        return Ok(xdp_action::XDP_PASS);
    }
    let payload_len = (data_end - (data + payload_offset as usize)) as u32;
    if payload_len == 0 || payload_len > 1500 {
        return Ok(xdp_action::XDP_PASS);
    }

    // ── 8. Reserve ring buffer entry ──
    let meta_size = mem::size_of::<PktMeta>() as u32; // 8
    let total_len = meta_size + payload_len;
    if total_len > 2064 {
        return Ok(xdp_action::XDP_PASS);
    }

    let mut entry = match PAYLOADS.reserve::<[u8; 2064]>(0) {
        Some(e) => e,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // ── 9. Write metadata ──
    let meta = PktMeta {
        src_ip,
        src_port,
        payload_len: payload_len as u16,
    };
    let entry_ptr = entry.as_mut_ptr() as *mut u8;
    let meta_ptr = &meta as *const PktMeta as *const u8;
    unsafe {
        *entry_ptr.add(0) = *meta_ptr.add(0);
        *entry_ptr.add(1) = *meta_ptr.add(1);
        *entry_ptr.add(2) = *meta_ptr.add(2);
        *entry_ptr.add(3) = *meta_ptr.add(3);
        *entry_ptr.add(4) = *meta_ptr.add(4);
        *entry_ptr.add(5) = *meta_ptr.add(5);
        *entry_ptr.add(6) = *meta_ptr.add(6);
        *entry_ptr.add(7) = *meta_ptr.add(7);
    }

    // ── 10. Copy payload using bpf_xdp_load_bytes ──
    // The BPF verifier needs to know the length argument is in [1, MAX].
    // LLVM cannot propagate range info across opaque asm boundaries, so we use
    // a single asm block that: masks the value AND conditionally jumps past the
    // helper call if it's zero. The verifier sees the branch and knows that
    // on the fall-through path the value is >= 1.
    let payload_dst = unsafe { entry_ptr.add(meta_size as usize) };
    let ctx_ptr = ctx.ctx;
    let copied_len: i64;

    // Safety: payload_offset and payload_len are both bounded and checked above.
    unsafe {
        core::arch::asm!(
            // r2 = payload_len & 0x7FF  →  verifier: r2 ∈ [0, 2047]
            "r2 = r4",
            "r2 &= 2047",
            // if r2 == 0, skip the helper call
            "if r2 == 0 goto +6",
            // bpf_xdp_load_bytes(ctx, offset, dst, len) — args in r1-r4
            "r1 = r7",          // r1 = ctx
            "r4 = r2",          // r4 = len (verifier: [1, 2047] on this path)
            "r2 = r8",          // r2 = payload_offset
            "r3 = r5",          // r3 = dst buffer
            "call 189",         // bpf_xdp_load_bytes
            "goto +1",
            // zero case: set return to -1 (error)
            "r0 = -1",
            in("r4") payload_len,
            in("r5") payload_dst,
            in("r7") ctx_ptr,
            in("r8") payload_offset,
            out("r0") copied_len,
            // clobbers
            lateout("r1") _,
            lateout("r2") _,
            lateout("r3") _,
            lateout("r4") _,
        );
    }
    if copied_len < 0 {
        entry.discard(0);
        return Ok(xdp_action::XDP_PASS);
    }

    // ── 11. Submit ──
    entry.submit(0);

    // ── 12. Update counter ──
    let ck: u32 = 0;
    if let Some(c) = unsafe { PKT_COUNT.get(&ck) } {
        let _ = PKT_COUNT.insert(&ck, &(*c + 1), 0);
    } else {
        let _ = PKT_COUNT.insert(&ck, &1u64, 0);
    }

    Ok(xdp_action::XDP_DROP)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
