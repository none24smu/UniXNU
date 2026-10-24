// SPDX-License-Identifier: BSD-2-Clause-Patent
// Polling USB 2 CDC ACM console for a DWC3 controller prepared by firmware.
// No firmware services are called. The ADT supplies the controller aperture.
// This does not initialize board clocks, PHYs or an IOMMU translation domain.
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#ifndef UNIXNU_DWC3_HOST_TEST
#include <machine/machine_routines.h>
#include <pexpert/device_tree.h>
extern vm_offset_t ml_static_vtop(vm_offset_t);
#endif

#define EVENT_BYTES 4096u
#define RING_BYTES 32768u
#define EP_COUNT 6u
#define GCTL 0xc110u
#define GSNPSID 0xc120u
#define GEVNTADRLO 0xc400u
#define GEVNTADRHI 0xc404u
#define GEVNTSIZ 0xc408u
#define GEVNTCOUNT 0xc40cu
#define DCFG 0xc700u
#define DCTL 0xc704u
#define DEVTEN 0xc708u
#define DSTS 0xc70cu
#define DALEPENA 0xc720u
#define DEP(n) (0xc800u + (n) * 16u)
#define TRB_HWO 1u
#define TRB_LAST 2u
#define TRB_IOC (1u << 11)
#define TRB_SHORT (1u << 10)

struct trb { uint32_t low, high, size, control; };
// Separate cache lines prevent CPU cache maintenance from losing adjacent DMA writes.
struct dma_area {
    uint32_t events[EVENT_BYTES / 4];
    struct trb trbs[EP_COUNT][4];
    uint8_t setup[64];
    uint8_t control[512];
    uint8_t transmit[512];
    uint8_t receive[512];
} __attribute__((aligned(4096)));
static struct dma_area dma;
static uintptr_t registers;
static uint64_t dma_physical, frequency;
static bool active, configured, busy, direction_in, three_stage, status_started, initialization_attempted;
static bool qcom_usb0;
static unsigned ep0_state, event_position, packet_size = 512, command_positions[2];
static uint32_t transfer_length[EP_COUNT], resources[EP_COUNT];
static bool transfer_active[EP_COUNT];
static uint8_t ring[RING_BYTES];
static uint64_t ring_head, ring_tail, transfer_end, reset_deadline;
volatile uint32_t unixnu_dwc3_phase, unixnu_dwc3_error, unixnu_dwc3_last_event;
volatile uint32_t unixnu_dwc3_last_command, unixnu_dwc3_last_command_status;
volatile uint64_t unixnu_dwc3_transmitted, unixnu_dwc3_dropped;
volatile uint32_t unixnu_dwc3_qcom_session_before, unixnu_dwc3_qcom_session_after;

#ifdef UNIXNU_DWC3_HOST_TEST
static uint64_t ticks(void);
static void cache_sync(void *, size_t);
static uint32_t read_reg(unsigned);
static void write_reg(unsigned, uint32_t);
static void reset_bootloader(void);
#else
static uint64_t ticks(void) { uint64_t value; __asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(value)); return value; }
static void cache_sync(void *address, size_t bytes)
{
    uint64_t ctr; __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uintptr_t line = 4ul << ((ctr >> 16) & 15), end = (uintptr_t)address + bytes;
    for (uintptr_t p = (uintptr_t)address & ~(line - 1); p < end; p += line)
        __asm__ volatile("dc civac, %0" :: "r"(p) : "memory");
    __asm__ volatile("dsb sy" ::: "memory");
}
static uint32_t read_reg(unsigned offset) { return *(volatile uint32_t *)(registers + offset); }
static void write_reg(unsigned offset, uint32_t value)
{
    *(volatile uint32_t *)(registers + offset) = value;
    __asm__ volatile("dsb sy" ::: "memory");
}
static void reset_bootloader(void)
{
    // Firmware already set the board's bootloader reason before handoff.
    register uint64_t x0 __asm__("x0") = 0x84000009;
    register uint64_t x1 __asm__("x1") = 0, x2 __asm__("x2") = 0, x3 __asm__("x3") = 0;
    __asm__ volatile("smc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3) : "memory");
}
#endif

static uint64_t physical(void *p) { return dma_physical + (uintptr_t)p - (uintptr_t)&dma; }
static bool command(unsigned ep, unsigned cmd, uint32_t p0, uint32_t p1, uint32_t p2)
{
    if (ep >= EP_COUNT) return false;
    write_reg(DEP(ep), p2); write_reg(DEP(ep) + 4, p1); write_reg(DEP(ep) + 8, p0);
    unixnu_dwc3_last_command = (ep << 16) | cmd;
    write_reg(DEP(ep) + 12, cmd | (1u << 10));
    uint64_t deadline = ticks() + frequency / 100; // 10 ms, no scheduler dependency
    uint32_t result;
    do {
        result = read_reg(DEP(ep) + 12);
        if (!(result & (1u << 10))) {
            unixnu_dwc3_last_command_status = result;
            if (result & 0xf000) { unixnu_dwc3_error = 2; return false; }
            if ((cmd & 15) == 6) resources[ep] = (result >> 16) & 127;
            return true;
        }
    } while (ticks() < deadline);
    unixnu_dwc3_error = 1;
    return false;
}
static void end_transfer(unsigned ep)
{
    if (transfer_active[ep]) (void)command(ep, 8 | (1u << 11) | (resources[ep] << 16), 0, 0, 0);
    transfer_active[ep] = false; resources[ep] = 0;
}
static bool endpoint(unsigned ep, unsigned type, unsigned packet, bool modify)
{
    uint32_t p0 = (type << 1) | (packet << 3) | ((ep & 1) ? ((ep >> 1) << 17) : 0);
    if (modify) p0 |= 2u << 30;
    uint32_t p1 = (ep << 25) | (1u << 8) | ((type == 0) ? (1u << 10) : (1u << 9));
    if (type == 3) p1 |= 8u << 16;
    if (!command(ep, 1, p0, p1, 0)) return false;
    write_reg(DALEPENA, read_reg(DALEPENA) | (1u << ep));
    return true;
}
static bool transfer(unsigned ep, void *buffer, unsigned bytes, unsigned type)
{
    if (ep >= EP_COUNT || bytes > 512 || transfer_active[ep]) return false;
    struct trb *trb = &dma.trbs[ep][0];
    uint64_t pa = physical(buffer), tp = physical(trb);
    trb->low = (uint32_t)pa; trb->high = (uint32_t)(pa >> 32); trb->size = bytes;
    trb->control = (type << 4) | TRB_HWO | TRB_LAST | TRB_IOC | TRB_SHORT;
    cache_sync(buffer, bytes); cache_sync(trb, 64);
    if (!command(ep, 6, (uint32_t)(tp >> 32), (uint32_t)tp, 0)) return false;
    transfer_length[ep] = bytes; transfer_active[ep] = true;
    return true;
}
static void arm_setup(void)
{
    end_transfer(0); end_transfer(1);
    ep0_state = 0; status_started = false;
    (void)transfer(0, dma.setup, 8, 2);
}
static void status_transfer(unsigned ep)
{
    if (status_started || ep0_state == 0) return;
    status_started = true; ep0_state = 2;
    (void)transfer(ep, dma.control, 0, three_stage ? 4 : 3);
}
static void stall_setup(void)
{
    (void)command(0, 4, 0, 0, 0);
    arm_setup();
}

static const uint8_t device_descriptor[] = {18,1,0,2,2,0,0,64,0x25,5,0xa7,0xa4,0,2,1,2,3,1};
static uint8_t configuration_descriptor[] = {
    9,2,67,0,2,1,0,0xc0,50, 9,4,0,0,1,2,2,0,0,
    5,0x24,0,0x10,1, 5,0x24,1,0,1, 4,0x24,2,2, 5,0x24,6,0,1,
    7,5,0x82,3,16,0,9, 9,4,1,0,2,0xa,0,0,0,
    7,5,0x81,2,0,2,0, 7,5,1,2,0,2,0
};
static const uint8_t qualifier[] = {10,6,0,2,2,0,0,64,1,0};
static const uint8_t languages[] = {4,3,9,4};
static const char *const strings[] = {"", "UniXNU", "zeta XNU log", "0"};
static uint8_t line_coding[7] = {0,0xc2,1,0,0,0,8}; // 115200, 8N1; USB transport is independent

static void control_in(const void *bytes, unsigned length, unsigned requested)
{
    if (length > requested) length = requested;
    if (length > sizeof(dma.control)) { stall_setup(); return; }
    memcpy(dma.control, bytes, length);
    ep0_state = 1;
    (void)transfer(1, dma.control, length, 5);
}
static void handle_setup(void)
{
    cache_sync(dma.setup, sizeof(dma.setup));
    const uint8_t *s = dma.setup;
    unsigned type = s[0], request = s[1], value = s[2] | (s[3] << 8);
    unsigned index = s[4] | (s[5] << 8), length = s[6] | (s[7] << 8);
    direction_in = (type & 128) != 0; three_stage = length != 0;
    status_started = false; ep0_state = length ? 1 : 2;
    if (type == 0x80 && request == 6) {
        unsigned descriptor = value >> 8, number = value & 255;
        if (descriptor == 1 && number == 0) control_in(device_descriptor, sizeof(device_descriptor), length);
        else if (descriptor == 2 && number == 0) control_in(configuration_descriptor, sizeof(configuration_descriptor), length);
        else if (descriptor == 6 && number == 0) control_in(qualifier, sizeof(qualifier), length);
        else if (descriptor == 3 && number == 0) control_in(languages, sizeof(languages), length);
        else if (descriptor == 3 && number < sizeof(strings)/sizeof(strings[0])) {
            uint8_t text[128]; unsigned count = 0;
            while (strings[number][count] && count < 63) { text[2 + 2*count] = (uint8_t)strings[number][count]; text[3 + 2*count] = 0; count++; }
            text[0] = (uint8_t)(2 + count*2); text[1] = 3; control_in(text, text[0], length);
        } else stall_setup();
    } else if (type == 0 && request == 5 && !length && value < 128) {
        write_reg(DCFG, (read_reg(DCFG) & ~(127u << 3)) | (value << 3));
    } else if (type == 0 && request == 9 && !length && value <= 1) {
        configured = false; end_transfer(2); end_transfer(3); end_transfer(5);
        write_reg(DALEPENA, 3);
        if (value == 1) {
            configured = endpoint(2, 2, packet_size, false) && endpoint(3, 2, packet_size, false) && endpoint(5, 3, 16, false);
            if (configured) { unixnu_dwc3_phase = 6; (void)transfer(2, dma.receive, 512, 1); }
            else stall_setup();
        }
    } else if (type == 0x80 && request == 8 && length == 1) {
        uint8_t config = configured ? 1 : 0; control_in(&config, 1, length);
    } else if ((type == 0x80 || type == 0x81 || type == 0x82) && request == 0 && length == 2) {
        uint8_t result[2] = {type == 0x80 ? 1 : 0, 0}; control_in(result, 2, length);
    } else if (type == 2 && request == 1 && value == 0 && !length && (index & 15) <= 2) {
        unsigned ep = ((index & 15) << 1) | ((index >> 7) & 1);
        (void)command(ep, 5, 0, 0, 0);
    } else if (type == 0x81 && request == 10 && length == 1 && index < 2) {
        uint8_t alt = 0; control_in(&alt, 1, length);
    } else if (type == 1 && request == 11 && !length && !value && index < 2) {
        // Only alternate setting zero exists.
    } else if (type == 0xa1 && request == 0x21 && index == 0 && length == 7) {
        control_in(line_coding, 7, length);
    } else if (type == 0x21 && request == 0x20 && index == 0 && length == 7) {
        (void)transfer(0, dma.control, 64, 5);
    } else if (type == 0x21 && (request == 0x22 || request == 0x23) && index == 0 && !length) {
        // Control lines/break do not change the byte transport.
    } else stall_setup();
}

static void append(uint8_t byte)
{
    if (ring_head - ring_tail == RING_BYTES) { ring_tail++; unixnu_dwc3_dropped++; }
    ring[ring_head++ % RING_BYTES] = byte;
}
static void send_pending(void)
{
    if (!configured || transfer_active[3] || ring_head == ring_tail) return;
    unsigned bytes = (unsigned)(ring_head - ring_tail);
    if (bytes > sizeof(dma.transmit)) bytes = sizeof(dma.transmit);
    for (unsigned i = 0; i < bytes; i++) dma.transmit[i] = ring[(ring_tail + i) % RING_BYTES];
    if (transfer(3, dma.transmit, bytes, 1)) transfer_end = ring_tail + bytes;
}
// Host commands on the log's OUT endpoint, each "\0ZETA:<name>\n": return to the bootloader, or count one Home press for the board's
// HID input (zeta kits/zeta/HidInputProbe.cpp reads unixnu_dwc3_home_requests).
volatile uint32_t unixnu_dwc3_home_requests;
static void receive_command(unsigned length)
{
    static const char *const commands[] = {"\0ZETA:REBOOT-BOOTLOADER\n", "\0ZETA:HOME\n"};
    static const unsigned lengths[] = {sizeof("\0ZETA:REBOOT-BOOTLOADER\n") - 1, sizeof("\0ZETA:HOME\n") - 1};
    cache_sync(dma.receive, sizeof(dma.receive));
    for (unsigned i = 0; i < length; i++) {
        uint8_t c = dma.receive[i];
        for (unsigned k = 0; k < 2; k++) {
            if (c != (uint8_t)commands[k][command_positions[k]]) { command_positions[k] = c == 0 ? 1 : 0; continue; }
            if (++command_positions[k] != lengths[k]) continue;
            command_positions[k] = 0;
            if (k == 0) {
                static const char reply[] = "XNUUSB: returning to bootloader\n";
                for (unsigned j = 0; j < sizeof(reply) - 1; j++) append((uint8_t)reply[j]);
                reset_deadline = ticks() + frequency / 5;
            } else unixnu_dwc3_home_requests = unixnu_dwc3_home_requests + 1;
        }
    }
}
static void endpoint_event(uint32_t event)
{
    unsigned ep = (event >> 1) & 31, kind = (event >> 6) & 15, status = (event >> 12) & 15;
    if (ep >= EP_COUNT) return;
    if (kind == 3 && ep <= 1 && (status & 3) == 2) { status_transfer(ep); return; }
    if (kind != 1 && kind != 2) return;
    if (!transfer_active[ep]) return;
    cache_sync(&dma.trbs[ep][0], 64);
    if (dma.trbs[ep][0].control & TRB_HWO) return;
    unsigned remaining = dma.trbs[ep][0].size & 0xffffff;
    if (remaining > transfer_length[ep]) { unixnu_dwc3_error = 3; return; }
    unsigned completed = transfer_length[ep] - remaining;
    transfer_active[ep] = false; resources[ep] = 0;
    if (ep <= 1) {
        if (ep0_state == 0) handle_setup();
        else if (ep0_state == 2) arm_setup();
        else {
            if (!direction_in && completed == 7) { cache_sync(dma.control, sizeof(dma.control)); memcpy(line_coding, dma.control, 7); }
            // Status is armed only upon the controller's XferNotReady status event.
            ep0_state = 2;
        }
    } else if (ep == 3) {
        uint64_t completed_end = transfer_end - remaining;
        unixnu_dwc3_transmitted += completed;
        if (completed_end > ring_tail) ring_tail = completed_end;
        unixnu_dwc3_phase = 7;
    } else if (ep == 2) {
        receive_command(completed);
        if (configured) (void)transfer(2, dma.receive, 512, 1);
    }
}

void unixnu_dwc3_poll(void)
{
    if (!active || __atomic_exchange_n(&busy, true, __ATOMIC_ACQUIRE)) return;
    unsigned bytes = read_reg(GEVNTCOUNT) & 0xfffc;
    if (bytes > EVENT_BYTES) { unixnu_dwc3_error = 5; bytes = EVENT_BYTES; }
    if (bytes > 256) bytes = 256; // Bound work in a timer interrupt.
    cache_sync(dma.events, EVENT_BYTES);
    for (unsigned i = 0; i < bytes; i += 4) {
        uint32_t event = dma.events[event_position / 4]; event_position = (event_position + 4) % EVENT_BYTES;
        unixnu_dwc3_last_event = event;
        if (!(event & 1)) endpoint_event(event);
        else if (((event >> 1) & 127) == 0) {
            unsigned kind = (event >> 8) & 15;
            if (kind == 0 || kind == 1) {
                configured = false; command_positions[0] = command_positions[1] = 0;
                for (unsigned ep = 0; ep < EP_COUNT; ep++) end_transfer(ep);
                write_reg(DCFG, read_reg(DCFG) & ~(127u << 3));
                if (kind == 1) arm_setup();
            } else if (kind == 2) {
                unixnu_dwc3_phase = 5;
                packet_size = ((read_reg(DSTS) & 7) == 0) ? 512 : 64;
                configuration_descriptor[57] = (uint8_t)packet_size; configuration_descriptor[58] = (uint8_t)(packet_size >> 8);
                configuration_descriptor[64] = (uint8_t)packet_size; configuration_descriptor[65] = (uint8_t)(packet_size >> 8);
                (void)endpoint(0, 0, 64, true); (void)endpoint(1, 0, 64, true);
            }
        }
        write_reg(GEVNTCOUNT, 4);
    }
    send_pending();
    if (reset_deadline && (ring_tail == ring_head || ticks() >= reset_deadline)) reset_bootloader();
    __atomic_store_n(&busy, false, __ATOMIC_RELEASE);
}
unsigned int unixnu_dwc3_ready(void) { unixnu_dwc3_poll(); return 1; }
void unixnu_dwc3_put(uint8_t byte) { append(byte); unixnu_dwc3_poll(); }
unsigned int unixnu_dwc3_receive_ready(void) { unixnu_dwc3_poll(); return 0; }
uint8_t unixnu_dwc3_receive(void) { return 0; }

bool unixnu_dwc3_init(void)
{
    // serial_init is called again by PE_init_kprintf. Preserve live transfers,
    // buffered output and an enumeration in progress instead of resetting USB.
    if (initialization_attempted) return active;
#ifndef UNIXNU_DWC3_HOST_TEST
    DTEntry chosen; const void *property; unsigned bytes;
    if (SecureDTLookupEntry(NULL, "/chosen", &chosen) != kSuccess ||
        SecureDTGetProperty(chosen, "unixnu,dwc3-console", &property, &bytes) != kSuccess || bytes != 16) return false;
    uint64_t window[2]; memcpy(window, property, sizeof(window));
    if (!window[0] || window[0] % 4096 || window[1] < 0xd000 || window[1] > 0x100000) return false;
    if (SecureDTGetProperty(chosen, "unixnu,qcom-usb0", &property, &bytes) == kSuccess) {
        uint32_t enabled;
        if (bytes != sizeof(enabled)) return false;
        memcpy(&enabled, property, sizeof(enabled));
        if (enabled != 1 || window[0] != 0x0a600000 || window[1] < 0xf8814) return false;
        qcom_usb0 = true;
    }
    initialization_attempted = true;
    registers = ml_io_map((vm_offset_t)window[0], (vm_size_t)window[1]);
    if (!registers) return false;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(frequency));
    dma_physical = ml_static_vtop((vm_offset_t)&dma);
#endif
    initialization_attempted = true;
    if (!frequency || !dma_physical) return false;
    unixnu_dwc3_phase = 1;
    uint32_t id = read_reg(GSNPSID) >> 16;
    if (id != 0x5533 && id != 0x3331) return false;
    write_reg(DCTL, (read_reg(DCTL) & ~(1u << 31)) | (1u << 30));
    uint64_t deadline = ticks() + frequency / 10;
    while (read_reg(DCTL) & (1u << 30)) if (ticks() >= deadline) { unixnu_dwc3_error = 6; return false; }
    unixnu_dwc3_phase = 2;
    write_reg(GCTL, (read_reg(GCTL) & ~((3u << 12) | (3u << 4) | (1u << 1) | (1u << 3))) |
              (2u << 12) | (qcom_usb0 ? 1u : 0)); // lahaina DT: disable-clk-gating
    // Keep firmware's UTMI width and PHY tuning; clear USB2 PHY suspend/sleep gating.
    write_reg(0xc200, read_reg(0xc200) & ~((1u << 6) | (1u << 8)));
    if (qcom_usb0) {
        // SM8350 QSCRATCH HS_PHY_CTRL, as in dwc3-qcom's VBUS override.
        // USB is attached to a host; select and assert UTMI session validity.
        // This does not initialize external PHY supplies or clocks.
        unixnu_dwc3_qcom_session_before = read_reg(0xf8810);
        write_reg(0xf8810, unixnu_dwc3_qcom_session_before | (1u << 20) | (1u << 28));
        unixnu_dwc3_qcom_session_after = read_reg(0xf8810);
    }
    memset(&dma, 0, sizeof(dma)); cache_sync(&dma, sizeof(dma));
    write_reg(GEVNTADRLO, (uint32_t)dma_physical); write_reg(GEVNTADRHI, (uint32_t)(dma_physical >> 32));
    write_reg(GEVNTSIZ, EVENT_BYTES | (1u << 31)); write_reg(GEVNTCOUNT, read_reg(GEVNTCOUNT) & 0xfffc);
    write_reg(DCFG, read_reg(DCFG) & ~((127u << 3) | 7u)); // High speed, address zero
    write_reg(DEVTEN, 7); write_reg(DALEPENA, 0);
    if (!command(0, 9, 0, 0, 0)) return false;
    for (unsigned ep = 0; ep < EP_COUNT; ep++) if (!command(ep, 2, 1, 0, 0)) return false;
    if (!endpoint(0, 0, 64, false) || !endpoint(1, 0, 64, false)) return false;
    unixnu_dwc3_phase = 3;
    arm_setup();
    if (!transfer_active[0]) return false;
    active = true;
    write_reg(DCTL, read_reg(DCTL) | (1u << 31));
    unixnu_dwc3_phase = 4;
    deadline = ticks() + frequency * 8;
    while (!configured && ticks() < deadline) unixnu_dwc3_poll();
    if (configured) {
        static const char banner[] = "XNUUSB: native DWC3 console ready\n";
        for (unsigned i = 0; i < sizeof(banner) - 1; i++) append((uint8_t)banner[i]);
        uint64_t flush = ticks() + frequency / 2;
        while (ring_head != ring_tail && ticks() < flush) unixnu_dwc3_poll();
    }
    // Register the byte sink even if Linux enumerates later. Early boot text
    // stays in the ring and polling continues from output and timer callbacks.
    return active;
}
