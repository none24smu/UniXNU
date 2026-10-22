// SPDX-License-Identifier: BSD-2-Clause-Patent
// Device protocol tests with DMA/MMIO stand-ins, not hardware qualification.
#define UNIXNU_DWC3_HOST_TEST 1
#include "native-dwc3-console.c"
#include <assert.h>
#include <stdio.h>

static uint32_t fake_registers[0x100000 / 4];
static uint64_t test_time;
static unsigned resets, stalls;
static bool command_timeout;
static uint64_t ticks(void) { return ++test_time; }
static void cache_sync(void *address, size_t bytes) { (void)address; (void)bytes; }
static uint32_t read_reg(unsigned offset) { assert(offset < sizeof(fake_registers)); return fake_registers[offset/4]; }
static void write_reg(unsigned offset, uint32_t value)
{
    assert(registers && offset < sizeof(fake_registers));
    if (offset == GEVNTCOUNT) { assert(value <= fake_registers[offset/4]); fake_registers[offset/4] -= value; }
    else if (offset == DCTL) fake_registers[offset/4] = value & ~(1u << 30);
    else if (offset >= DEP(0) && offset <= DEP(5) + 12 && offset % 16 == 12) {
        if ((value & 15) == 4) stalls++;
        fake_registers[offset/4] = command_timeout ? value : ((value & ~((1u << 10) | 0xf000u)) | (1u << 16));
    } else fake_registers[offset/4] = value;
}
static void reset_bootloader(void) { resets++; reset_deadline = 0; }
static void event(uint32_t value)
{
    dma.events[event_position/4] = value;
    fake_registers[GEVNTCOUNT/4] = 4;
    unixnu_dwc3_poll();
    assert(fake_registers[GEVNTCOUNT/4] == 0);
}
static void complete(unsigned ep, unsigned remaining)
{
    assert(transfer_active[ep]);
    dma.trbs[ep][0].control &= ~TRB_HWO; dma.trbs[ep][0].size = remaining;
    event((ep << 1) | (1u << 6));
}
static void setup(unsigned type, unsigned request, unsigned value, unsigned index, unsigned length)
{
    assert(ep0_state == 0 && transfer_active[0]);
    uint8_t bytes[8] = {(uint8_t)type,(uint8_t)request,(uint8_t)value,(uint8_t)(value>>8),
                        (uint8_t)index,(uint8_t)(index>>8),(uint8_t)length,(uint8_t)(length>>8)};
    memcpy(dma.setup, bytes, 8); complete(0,0);
}
static void finish_control_in(void)
{
    complete(1,0); assert(ep0_state == 2);
    event((3u << 6) | (2u << 12));
    assert(transfer_active[0] && ((dma.trbs[0][0].control >> 4) & 63) == 4);
    complete(0,0); assert(ep0_state == 0);
}
static void finish_no_data(void)
{
    event((1u << 1) | (3u << 6) | (2u << 12));
    assert(transfer_active[1] && ((dma.trbs[1][0].control >> 4) & 63) == 3);
    complete(1,0); assert(ep0_state == 0);
}
int main(void)
{
    registers=1; frequency=1000; dma_physical=0x100000;
    qcom_usb0=true;
    fake_registers[0xf8810/4]=0x42;
    fake_registers[GSNPSID/4]=0x5533330a;
    assert(unixnu_dwc3_init() && active && !configured && unixnu_dwc3_phase==4); // No simulated host yet; bounded wait.
    assert(fake_registers[0xf8810/4]==(0x42 | (1u<<20) | (1u<<28)));
    uint64_t initialized_at=test_time;
    unixnu_dwc3_put('E');
    assert(unixnu_dwc3_init() && test_time==initialized_at && ring_head==1); // No second reset or enumeration wait.
    assert(sizeof(configuration_descriptor)==67);
    event(1u | (1u << 8)); event(1u | (2u << 8));
    setup(0x80,6,0x100,0,65535); assert(transfer_length[1]==18 && dma.control[0]==18); finish_control_in();
    setup(0x80,6,0x200,0,255); assert(transfer_length[1]==67 && dma.control[2]==67); finish_control_in();
    setup(0x80,6,0x302,0x409,255); assert(transfer_length[1]==26 && dma.control[2]=='z'); finish_control_in();
    setup(0,5,17,0,0); assert(((read_reg(DCFG)>>3)&127)==17); finish_no_data();
    setup(0,9,1,0,0); assert(configured && transfer_active[2]); finish_no_data();
    assert(transfer_active[3] && dma.transmit[0]=='E'); complete(3,0);
    ring_head=ring_tail=0; // Early text was delivered; subsequent completion cases start empty.
    setup(0xa1,0x21,0,0,7); assert(transfer_length[1]==7 && dma.control[6]==8); finish_control_in();
    setup(0x21,0x20,0,0,7); memcpy(dma.control,(uint8_t[]){0,0x96,0,0,0,0,8},7);
    complete(0,57); event((1u<<1)|(3u<<6)|(2u<<12)); complete(1,0); assert(line_coding[1]==0x96);
    setup(0x21,0x22,3,0,0); finish_no_data();
    unsigned before=stalls; setup(0x80,6,0xff00,0,255); assert(stalls==before+1 && ep0_state==0);
    unixnu_dwc3_put('A'); unixnu_dwc3_put('B'); assert(ring_tail==0 && dma.transmit[0]=='A');
    complete(3,0); assert(ring_tail==1 && dma.transmit[0]=='B'); complete(3,0); assert(ring_tail==ring_head);
    append('C');append('D');send_pending();complete(3,1);assert(dma.transmit[0]=='D');complete(3,0);assert(ring_tail==ring_head);
    // The reboot frame must survive separate USB OUT completions.
    memcpy(dma.receive,"\0ZETA:REBOOT-",13); complete(2,512-13);
    memcpy(dma.receive,"BOOTLOADER\n",11); complete(2,512-11);
    assert(reset_deadline && !resets);
    while (transfer_active[3]) complete(3,0);
    assert(resets==1);
    command_timeout=true; uint64_t start=test_time;assert(!command(1,1,0,0,0));assert(test_time-start<100);
    puts("PASS: CDC descriptors, EP0 data/status phases, line coding, refusal, DMA completion accounting, split reboot frame and bounded command timeout; hardware I/O substituted");
}
