//! HBA structures
//!
//! Based on [Serial ATA AHCI: Specification, Rev. 1.3.1].
//! In this module, "See spec section N" makes reference to this document.
//!
//! [Serial ATA AHCI: Specification, Rev. 1.3.1]: http://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/serial-ata-ahci-spec-rev1-3-1.pdf

use kfs_libuser::io::{Io, Mmio};
use kfs_libuser::syscalls::{sleep_thread, query_physical_address};
use kfs_libuser::mem::{map_mmio, virt_to_phys};
use kfs_libuser::error::{Error, AhciError};
use kfs_libuser::zero_box::*;
use core::fmt::{self, Debug, Formatter};
use core::mem::size_of;
use core::cmp::min;
use core::time::Duration;
use alloc::prelude::*;
use crate::fis::*;
use crate::disk::Disk;
use static_assertions::assert_eq_size;

// ---------------------------------------------------------------------------------------------- //
//                                              Hba                                               //
// ---------------------------------------------------------------------------------------------- //

/// HBA memory registers.
///
/// See spec section 3.1
///
/// Found at address in pci configuration register `BAR5`.
#[allow(clippy::missing_docs_in_private_items)]
#[repr(packed)]
pub struct HbaMemoryRegisters {
    generic_host_control: GenericHostControl, // 0x00 - 0x2b, generic host control registers
    _rsv:        [Mmio<u8>; 116], // 0x2c - 0x9f, reserved
    _rsv_vendor: [Mmio<u8>; 96], // 0xa0 - 0xff, vendor specific registers
    ports:       [Px; 32], // 0x0100 - 0x10ff, port control registers
}

/// HBA Generic Host Control.
///
/// See spec section 3.1
///
/// Found at address in pci configuration register `BAR5[0x00]-BAR5[0x2B]`.
#[allow(clippy::missing_docs_in_private_items)]
#[repr(packed)]
pub struct GenericHostControl {
    cap: Mmio<CAP>, // 0x00, host capability
    ghc: Mmio<GHC>, // 0x04, global host control
    is: Mmio<u32>, // 0x08, interrupt status
    pi: Mmio<u32>, // 0x0c, port implemented
    vs: Mmio<u32>, // 0x10, version
    ccc_ctl: Mmio<u32>, // 0x14, command completion coalescing control
    ccc_pts: Mmio<u32>, // 0x18, command completion coalescing ports
    em_loc: Mmio<u32>, // 0x1c, enclosure management location
    em_ctl: Mmio<u32>, // 0x20, enclosure management control
    cap2: Mmio<CAP2>, // 0x24, host capabilities extended
    bohc: Mmio<u32>, // 0x28, bios/os handoff control and status
}

impl Debug for GenericHostControl {
    /// Debug does not access reserved registers.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("HbaMem")
            .field("cap", &self.cap)
            .field("ghc", &self.ghc)
            .field("is", &self.is)
            .field("pi", &self.pi)
            .field("vs", &self.vs)
            .field("ccc_ctl", &self.ccc_ctl)
            .field("ccc_pts", &self.ccc_pts)
            .field("em_loc", &self.em_loc)
            .field("em_ctl", &self.em_ctl)
            .field("cap2", &self.cap2)
            .field("bohc", &self.bohc)
//            .field("vendor", &"-omitted-")
//            .field("ports", &self.iter_ports())
            .finish()
    }
}

bitfield!{
    /// HbaMem.CAP "HBA Capabilities" register bitfield.
    ///
    /// Defined in section 3.1.1
    #[derive(Clone, Copy)]
    struct CAP(u32);
    impl Debug;
    s64a,     _: 31;
    sncq,     _: 30;
    ssntf,    _: 29;
    smps,     _: 28;
    sss,      _: 27;
    salp,     _: 26;
    sal,      _: 25;
    sclo,     _: 24;
    iss,      _: 23, 20;
    // 19 reserved
    sam,      _: 18;
    spm,      _: 17;
    fbss,     _: 16;
    pmd,      _: 15;
    scc,      _: 14;
    psc,      _: 13;
    ncs,      _: 12, 8;
    cccs,     _: 7;
    ems,      _: 6;
    sxs,      _: 5;
    np,       _: 4, 0;
}

bitfield!{
    /// HbaMem.GHC "Global HBA Control" register bitfield.
    ///
    /// Defined in section 3.1.2
    #[derive(Clone, Copy)]
    struct GHC(u32);
    impl Debug;
    ae,  set_ae: 31;
    // 30:03 reserved
    mrsm,     _: 2;
    ie,  set_ie: 1;
    hr,  set_hr: 0;
}

bitfield!{
    /// HbaMem.CAP2 "HBA Capabilities Extended" register bitfield.
    ///
    /// Defined in section 3.1.10
    #[derive(Clone, Copy)]
    struct CAP2(u32);
    impl Debug;
    // 31:06 reserved
    deso,     _: 5;
    sadm,     _: 4;
    sds,      _: 3;
    apst,     _: 2;
    nvmp,     _: 1;
    boh,      _: 0;
}

/*
/// An iterator that yields only implemented ports, according to `PI`.
///
/// Returns (`port_index`, `reference_to_port`).
pub struct PortIterator<'a> {
    ports: &'a mut [Px; 32],
    pi: u32,
    pos: usize,
}

impl<'a> Iterator for PortIterator<'a> {
    type Item = (usize, &'a mut Px);

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        while self.pos < 32 {
            if (self.pi & (1 << self.pos)) != 0 {
                // this port is implemented
                self.pos += 1;
                return  Some((self.pos - 1, &mut self.ports[self.pos - 1]));
            }
            self.pos += 1;
        }
        None
    }
}

impl Debug for PortIterator<'_> {
    /// Debug prints the implemented port array.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        f.debug_list()
            .entries(self.clone())
            .finish()
    }
}
*/

impl HbaMemoryRegisters {
    /// Initializes an AHCI Controller.
    ///
    /// `BAR5` is the physical address of HBA Memory Register, usually obtained via PCI discovery.
    ///
    /// This function will map the root Mmio region, allocate memory for every 'implemented' port,
    /// put them in the running state, and return an interface to the plugged devices which is up and running.
    ///
    /// # Error
    ///
    /// If an error occurred, this function will stop trying to initialize the HBA and return an
    /// empty Vec as if no disks were found. This can happen if:
    ///
    /// * mapping `BAR5` failed.
    /// * GHC.AE is not set (controller is in legacy support mode), because conditions specified in
    ///   section 10.2 are tedious.
    pub fn init(bar5: usize) -> Vec<Disk> {
        let mapping = match map_mmio::<HbaMemoryRegisters>(bar5 as _) {
            Ok(vaddr) => vaddr,
            Err(e) => {
                error!("HBA {:#010x}, initialization failed: failed mapping BAR5, {:?}.", bar5, e);
                return Vec::new()
            }
        };
        let ghc_registers = unsafe {
            // constructing a reference to the Generic Host Control registers we just mapped.
            // safe, nobody has a reference to it yet.
            &mut (*mapping).generic_host_control
        };
        // check that system software is AHCI aware by setting GHC.AE to ‘1’.
        if !ghc_registers.ghc.read().ae() {
            error!("HBA {:#010x}, initialization failed: controller is in legacy support mode.", bar5);
            return Vec::new();
        }

        // globally disable interrupts for this controller
        let mut ghc = ghc_registers.ghc.read();
        ghc.set_ie(false);
        ghc_registers.ghc.write(ghc);

        let command_list_len = ghc_registers.cap.read().ncs() as usize + 1;
        let pi = ghc_registers.pi.read();

        let port_registers = unsafe {
            // constructing a reference to the port registers we previously mapped.
            // safe, it is the only reference to this memory area.
            // the reference's lifetime is tied to the returned Disk structure,
            // which will never outlive the mapping.
            &mut (*mapping).ports
        };
        // Initialize ports marked implemented by PI.
        port_registers.iter_mut()
            .enumerate()
            // filter out ports not implemented
            .filter(|(index, _)| (pi & (1u32 << index)) != 0)
            // init each port, keep only successful ones
            .filter_map(|(_port_index, px)| Px::init(px, command_list_len))
            // put that in a vec
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------- //
//                                         Port Registers                                         //
// ---------------------------------------------------------------------------------------------- //

/// HBA Memory Port registers.
///
/// See spec section 3.3
///
/// An array of 1 to 32 Px is found at BAR5 + 0x0100-0x10FF.
///
/// The list of ports that are actually implemented can be found in `HBA.PI`.
/// Px not implemented must never be accessed.
#[allow(clippy::missing_docs_in_private_items)]
#[repr(packed)]
pub struct Px {
    clb: Mmio<u64>, // 0x00, command list base address, 1K-byte aligned
    fb: Mmio<u64>, // 0x08, FIS base address, 256-byte aligned
    is: Mmio<PxIS>, // 0x10, interrupt status
    ie: Mmio<PxIE>, // 0x14, interrupt enable
    cmd: Mmio<PxCMD>, // 0x18, command and status
    _rsv0: Mmio<u32>, // 0x1C, Reserved
    tfd: Mmio<PxTFD>, // 0x20, task file data
    sig: Mmio<u32>, // 0x24, signature
    ssts: Mmio<PxSSTS>, // 0x28, SATA status (SCR0:SStatus)
    sctl: Mmio<u32>, // 0x2C, SATA control (SCR2:SControl)
    serr: Mmio<u32>, // 0x30, SATA error (SCR1:SError)
    sact: Mmio<u32>, // 0x34, SATA active (SCR3:SActive)
    ci: Mmio<u32>, // 0x38, command issue
    sntf: Mmio<u32>, // 0x3C, SATA notification (SCR4:SNotification)
    fbs: Mmio<u32>, // 0x40, FIS-based switch control
    _rsv1: [Mmio<u32>; 11], // 0x44 ~ 0x6F, Reserved
    vendor: [Mmio<u32>; 4], // 0x70 ~ 0x7F, vendor specific
}

bitfield!{
    /// `PxIS` "Port x Interrupt status" register bitfield.
    ///
    /// A '1' indicates a pending interrupt. Write '1' to clear.
    /// Refer to spec for actions that must be taken on each interrupt.
    ///
    /// Defined in section 3.3.5
    #[derive(Clone, Copy)]
    struct PxIS(u32);
    impl Debug;
    cpds, set_cpds: 31;
    tfes, set_tfes: 30;
    hbfs, set_hbfs: 29;
    hbds, set_hbds: 28;
    ifs,  set_ifs : 27;
    infs, set_infs: 26;
    // 25 reserved
    ofs,  set_ofs : 24;
    ipms, set_ipms: 23;
    prcs,        _: 22;
    // 21:08 reserved
    dmps, set_dmps: 7;
    pcs,         _: 6;
    dps,  set_dps : 5;
    ufs,         _: 4;
    sbds, set_sbds: 3;
    dss,  set_dss : 2;
    pss,  set_pss : 1;
    dhrs, set_dhrs: 0;
}

impl PxIS {
    /// Checks if a PxIS has set any of the bits corresponding to an error.
    fn is_err(self) -> bool {
        self.tfes() || self.hbfs() || self.hbds() || self.ifs() || self.infs() || self.ofs()
    }
}

bitfield!{
    /// `PxIE` "Port x Interrupt Enable" register bitfield.
    ///
    /// This register enables and disables the reporting of the corresponding interrupt to system software.
    /// When a bit is set (‘1’) and the corresponding interrupt condition is active,
    /// then an interrupt is generated.
    /// Interrupt sources that are disabled (‘0’) are still reflected in the status registers.
    ///
    /// This register is symmetrical with the PxIS register.
    ///
    /// Defined in section 3.3.6
    #[derive(Clone, Copy)]
    struct PxIE(u32);
    impl Debug;
    cpde, set_cpde: 31;
    tfee, set_tfee: 30;
    hbfe, set_hbfe: 29;
    hbde, set_hbde: 28;
    ife,  set_ife : 27;
    infe, set_infe: 26;
    // 25 reserved
    ofe,  set_ofe : 24;
    ipme, set_ipme: 23;
    prce, set_prce: 22;
    // 21:08 reserved
    dmpe, set_dmpe: 7;
    pce,  set_pce : 6;
    dpe,  set_dpe : 5;
    ufe,  set_ufe : 4;
    sbde, set_sbde: 3;
    dse,  set_dse : 2;
    pse,  set_pse : 1;
    dhre, set_dhre: 0;
}

bitfield!{
    /// `PxCMD` "Port x Command and Status" register bitfield.
    ///
    /// Defined in section 3.3.7
    #[derive(Clone, Copy)]
    struct PxCMD(u32);
    impl Debug;
    cmd,   set_cmd  : 31,28;
    asp,   set_asp  : 27;
    alpe,  set_alpe : 26;
    dlae,  set_dlae : 25;
    atapi, set_atapi: 24;
    apste, set_apste: 23;
    fbscp,         _: 22;
    esp,           _: 21;
    cpd,           _: 20;
    mpsp,          _: 19;
    hpcp,          _: 18;
    pma,   set_pma  : 17;
    cps,           _: 16;
    cr,            _: 15;
    fr,            _: 14;
    mpss,          _: 13;
    ccs,           _: 12,8;
    // 07:05 reserved
    fre,   set_fre  : 4;
    clo,   set_clo  : 3;
    pod,   set_pod  : 2;
    sud,   set_sud  : 1;
    st,    set_st   : 0;
}

bitfield!{
    /// `PxTFD` "Port x Task File Data" register bitfield.
    ///
    /// Defined in section 3.3.8
    #[derive(Clone, Copy)]
    struct PxTFD(u32);
    impl Debug;
    // 31:16 reserved
    err,           _: 15,8;
    bsy,           _: 7;
    cs0,           _: 6,4;
    drq,           _: 3;
    cs1,           _: 2,1;
    err_flag,      _: 0;
}

bitfield!{
    /// `PxSSTS` "Port x Serial ATA Status" register bitfield.
    ///
    /// Defined in section 3.3.10
    #[derive(Clone, Copy)]
    struct PxSSTS(u32);
    impl Debug;
    // 31:12 reserved
    ipm,           _: 11,8;
    spd,           _: 7,4;
    det,           _: 3,0;
}

impl Debug for Px {
    /// Debug does not access reserved registers.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("HbaPort")
            .field("PxCLB-PxCLBU", &self.clb)
            .field("PxFB-PxFBU", &self.fb)
            .field("PxIS", &self.is)
            .field("PxIE", &self.ie)
            .field("PxCMD", &self.cmd)
            .field("PxTFD", &self.tfd)
            .field("PxSIG", &self.sig)
            .field("PxSSTS", &self.ssts)
            .field("PxSCTL", &self.sctl)
            .field("PxSERR", &self.serr)
            .field("PxSACT", &self.sact)
            .field("PxCI", &self.ci)
            .field("PxSNTF", &self.sntf)
            .field("PxFBS", &self.fbs)
            .field("PxVS", &"-omitted-")
            .finish()
    }
}

impl Px {
    /// Stop this port.
    ///
    /// Clears `PxCMD.ST`, and waits for `PxCMD.CR` to be cleared.
    pub fn stop(&mut self) {
        // clear PxCMD.ST
        let mut cmd = self.cmd.read();
        if cmd.st() || cmd.cr() {
            cmd.set_st(false);
            self.cmd.write(cmd);
            // 1. wait for 500ms.
            // 2. check PxCMD.CR is now cleared.
            while { // ugly do-while loop
                sleep_thread(Duration::from_millis(500).as_nanos() as _).unwrap(); // wait for 500ms.
                self.cmd.read().cr() // == true
            } {};
        }
        // from now on PxCMD.ST = 0, PxCMD.CR = 0.
    }

    /// Start this port.
    ///
    /// Makes `PxCLB` point to `command_list`,
    /// sets `PxCMD.ST`, and waits for `PxCMD.CR` to be set.
    ///
    /// See section 10.3.1 for conditions to meet before calling this function.
    ///
    /// # Unsafety
    ///
    /// Port will continue updating frames pointed to by `command_list`.
    /// To prevent that, `clear_addresses` must be called before `command_list` is outlived.
    ///
    /// # Panics
    ///
    /// * `PxCMD.FRE` is not set.
    /// * `PxCMD.CR` is already set.
    /// * A functional device is not present: `probe` returned false.
    unsafe fn start(&mut self, command_list: &mut CmdHeaderArray) {
        let mut cmd = self.cmd.read();
        assert_eq!(cmd.fre(), true, "Trying to start port: PxCMD.FRE is not set");
        assert_eq!(cmd.cr(), false, "Trying to start port: PxCMD.CR is already set");
        assert_eq!(self.probe(),    true, "Trying to start port: No device detected");
        // write PxCLB
        self.clb.write(
            virt_to_phys(command_list) as u64
        );
        // set PxCMD.ST
        cmd.set_st(true);
        self.cmd.write(cmd);
        // 1. wait for 500ms.
        // 2. check PxCMD.CR is now cleared.
        while { // ugly do-while loop
            sleep_thread(Duration::from_millis(1).as_nanos() as _).unwrap(); // wait a bit.
            !self.cmd.read().cr() // == false
        } {};
        // from now on PxCMD.ST = 1, PxCMD.CR = 1.
    }

    /// Disables FIS Receive.
    ///
    /// Clears `PxCMD.FRE`, and waits for `PxCMD.FR` to be cleared.
    ///
    /// See section 10.3.2 for conditions to meet before calling this function.
    ///
    /// # Panics
    ///
    /// * Port is running: `PxCMD.ST` or `PxCMD.CR` is set.
    pub fn disable_fis_receive(&mut self) {
        let mut cmd = self.cmd.read();
        assert_eq!(cmd.st() || cmd.cr(), false, "Trying to disable port FIS Receive: Port is running");
        if cmd.fre() || cmd.fr() {
            // clear PxCMD.FRE
            cmd.set_fre(false);
            self.cmd.write(cmd);
            // 1. wait for 500ms.
            // 2. wait check PxCMD.FR is now cleared.
            while { // ugly do-while loop
                sleep_thread(Duration::from_millis(500).as_nanos() as _).unwrap();
                self.cmd.read().fr() // == true
            } {};
        }
        // from now on PxCMD.FRE = 0, PxCMD.FR = 0.
    }

    /// Enable FIS Receive.
    ///
    /// Make `PxFB` point to `memory_area`, and sets `PxCMD.FRE`.
    ///
    /// # Unsafety
    ///
    /// Port will continue writing received FIS to `memory_area`.
    /// To prevent that, `clear_addresses` must be called before `memory_area` is outlived.
    ///
    /// # Panics
    ///
    /// * Port is running: `PxCMD.ST` or `PxCMD.CR` is set.
    /// * FIS Receive is already running: `PxCMD.FRE` or `PxCMD.FR` is set.
    pub unsafe fn enable_fis_receive(&mut self, memory_area: &mut ReceivedFis) {
        let mut cmd = self.cmd.read();
        assert_eq!(cmd.st()  || cmd.cr(), false, "Trying to enable port FIS Receive: Port is running");
        assert_eq!(cmd.fre() || cmd.fr(), false, "Trying to enable port FIS Receive: FIS Receive is already running");
        self.fb.write(
            virt_to_phys(memory_area) as u64
        );
        // set PxCMD.FRE
        cmd.set_fre(true);
        self.cmd.write(cmd);
        // wait for PxCMD.FR to be set
        while !self.cmd.read().fre() {
            sleep_thread(Duration::from_millis(1).as_nanos() as _).unwrap();
        };
        // from now on PxCMD.FRE = 1
    }

    /// Checks if a functional device is present on the port.
    ///
    /// Determined by `PxTFD.STS.BSY == 0 && PxTFD.STS.DRQ == 0 && (PxSSTS.DET = 3 || PxSSTS.IPM == (2,6,8)`
    fn probe(&self) -> bool {
        let tfd = self.tfd.read();
        let sts = self.ssts.read();

        !tfd.bsy() && !tfd.drq()
        && (sts.det() == 3 || { match sts.ipm() { 2 | 6 | 8 => true, _ => false } })
    }

    /// Makes `PxFB` and `PxCLB` point to `0x00000000`.
    ///
    /// This ensures HBA will not write to frames we may no longer own.
    ///
    /// This function will stop the port and disable FIS Receive.
    pub fn clear_addresses(&mut self) {
        self.stop();
        self.disable_fis_receive();
        self.clb.write(0x00000000 as u64);
        self.fb.write(0x00000000 as u64);
    }

    /// Initializes a port, returning a [Disk] to interface with it.
    ///
    /// If the port is not connected to anything, or initialisation failed,
    /// this function returns `None`.
    fn init(port_registers: &'static mut Px, command_list_length: usize) -> Option<Disk> {
        port_registers.stop();
        port_registers.disable_fis_receive();
        if !port_registers.probe() {
            // If we don't detect anything, don't bother initialising it, just return.
            port_registers.clear_addresses();
            return None;
        }

        port_registers.ie.write(PxIE(0x00)); // no interrupts
        let mut received_fis = ZeroBox::<ReceivedFis>::new_zeroed();
        unsafe {
            // safe: when the Disk is dropped we make sure to call `clear_addresses`.
            port_registers.enable_fis_receive(&mut *received_fis);
        }
        let mut cmd_list = ZeroBox::<CmdHeaderArray>::new_zeroed();
        // init the command list
        let mut cmd_tables: [Option<ZeroBox<CmdTable>>; 32] = Default::default();
        for (i, header) in cmd_list.slots[0..command_list_length].iter_mut().enumerate() {
            let mut table = ZeroBox::<CmdTable>::new_zeroed();
            unsafe {
                // safe: - `table` has just been allocated, it is not pointed to by anyone else.
                //       - port is stopped.
                header.init(&mut table);
            }
            cmd_tables[i] = Some(table);
        }
        unsafe {
            // safe: when the port is dropped we make sure to call `clear_addresses`.
            port_registers.start(&mut cmd_list);
        }
        // clear PxSERR by writing '1' to every non-reserved bit.
        // would have done a bitfield, but it provides no "set all" function.
        port_registers.serr.write(0b00000111111111110000111100000011u32);

        let (sectors, supports_48_bit) = unsafe {
            // safe: - port is started,
            //       - index is 0, which is always implemented (required by spec),
            //       - no command has been issued yet, so CI is clear.
            match Self::identify(port_registers, &mut cmd_list.slots[0], cmd_tables[0].as_mut().unwrap(), 0) {
                Ok(x) => x,
                Err(e) => {
                    error!("Initializing port failed: IDENTIFY DEVICE command failed. Error: {:?}. Status: {:?}", e, port_registers);
                    port_registers.stop();
                    port_registers.disable_fis_receive();
                    port_registers.clear_addresses();
                    return None
                }
            }
        };

        Some(Disk {
            px: port_registers,
            rfis: received_fis,
            cmd_list,
            cmd_tables,
            sectors,
            supports_48_bit
        })
    }

    /// Checks if the command issued in `slot` is still running.
    ///
    /// This function returns true either if the `slot` bit is cleared in `PxCI`, or if an error occurred.
    fn command_running(&self, slot: usize) -> bool {
        (self.ci.readf(1u32 << slot) || self.tfd.read().bsy()) && !self.is.read().is_err()
    }

    /// Polls the port until the command in `slot` is completed, or an error occurred.
    // todo: AHCI interrupts - command completion
    // body: The AHCI driver does not make any use of AHCI interruptions.
    // body: To check that a command has been completed, it polls the port repeatedly
    // body: until the PxCI bit cleared.
    // body:
    // body: This is bad for performances, uses unnecessary time slices, and is an
    // body: awful design.
    // body:
    // body: We need to figure out how to make AHCI interrupts work for us.
    // body:
    // body: The problem that we faced is the following:
    // body:
    // body: When enabled, after a command has completed, the HBA sends an irq to the PIC.
    // body: The irq kernel-side top-half `acknowledges the irq` (sends EOI to the 8259A),
    // body: and delays the actual handling to the userspace-side bottom-half.
    // body: It then rets to the interrupted context, and re-enables interrupts by doing so.
    // body:
    // body: At this point the HBA, whose state has not been resolved, re-triggers an interrupt.
    // body:
    // body: Hence the kernel is spending 100% cpu time servicing an infinite irq
    // body: and the OS completely freezes.
    // body:
    // body: This happens even while the 8359A is in `edge triggered mode`, which means that the
    // body: PCI irq line is cycling through an HIGH and LOW, which is really odd according to the
    // body: spec, where the irq are supposed to be "level sensitive".
    // body:
    // body: I think a little more digging up would be necessary to find out if we just configured
    // body: something incorrectly, or if AHCI interrupts truly cannot be handled in the bottom-half.
    // body:
    // body: In the few open-source microkernels I reviewed that have an AHCI driver:
    // body:
    // body: - Redox does not implement interrupts (well ... just like us),
    // body: - HelenOS seems to allow userspace drivers to have their own top-half routine.
    // body:   I don't know if they run in ring 0 or ring 3, how the page-tables switching is handled,
    // body:   but I'm really curious and will try to find out more about it.
    // body: - Minix3 seems to be actually using interrupts, through its blockdriver multithreading framework.
    // body:   I should look this up.
    fn wait_command_completion(&self, slot: usize) -> Result<(), Error> {
        while self.command_running(slot) {
            sleep_thread(0).unwrap();
        }
        if self.is.read().is_err() {
            Err(AhciError::IoError.into())
        } else {
            Ok(())
        }
    }

    /// Sends the IDENTIFY DEVICE command to a port to gather some information about it.
    ///
    /// # Returns
    ///
    /// - The number of addressable sectors this device possesses.
    /// - Whether the device supports 48-bit addresses.
    ///
    /// # Unsafety
    ///
    /// * The port must be started
    /// * `command_slot_index` must not have its bit set in `PxCI`.
    /// * `command_header` and `command_table` must belong to `command_slot_index`'s command slot.
    #[allow(clippy::cast_lossless)] // trust me, types won't change
    unsafe fn identify(px: &mut Px, command_header: &mut CmdHeader, command_table: &mut CmdTable, command_slot_index: usize) -> Result<(u64, bool), Error> {

        /// The IDENTIFY DEVICE command. See ATA spec.
        const ATA_CMD_IDENTIFY: u8 = 0xEC;

        /// The ouptut of the IDENTIFY command.
        ///
        /// Defined by ATA/ATAPI-5, with SATA modifications.
        #[repr(C, align(2))]
        struct IdentifyOutput {
            /// Array of words, filled by the IDENTIFY command.
            bytes: [u16; 256]
        }
        unsafe impl ZeroInitialized for IdentifyOutput {}

        let mut output = ZeroBox::<IdentifyOutput>::new_zeroed();

        // write the FIS
        let fis = &mut command_table.cfis.h2d;
        fis.fis_type.write(FisType::RegH2D as u8);
        fis.command.write(ATA_CMD_IDENTIFY);
        fis.pm.write(1 << 7); // this is an update of the Command register
        fis.device.write(0);

        // fill the prdt
        unsafe {
            // safe: `&mut output` points to valid memory.
            command_table.fill_prdt(&mut *output as *mut _ as _, size_of::<IdentifyOutput>(), command_header)?
        }

        // fill the command header
        let mut ch_flags = CmdHeaderFlags(0);
        ch_flags.set_c(true);
        ch_flags.set_w(false);
        ch_flags.set_cfl((size_of::<FisRegH2D>() / 4) as u16);
        command_header.flags.write(ch_flags);

        // set PxCI
        px.ci.write(1u32 << command_slot_index);
        px.wait_command_completion(command_slot_index)?;

        let mut supports_48_bit = true;

        // sectors count is found at output[100-103] for recent 48 bits devices, output[60-61] otherwise.
        let mut sectors = (output.bytes[100] as u64) |
            ((output.bytes[101] as u64) << 16) |
            ((output.bytes[102] as u64) << 32) |
            ((output.bytes[103] as u64) << 48);
        if sectors == 0 {
            sectors = (output.bytes[60] as u64) | ((output.bytes[61] as u64) << 16);
            supports_48_bit = false;
        };

        Ok((sectors, supports_48_bit))
    }

    /// Read `sector_count` contiguous sectors from the disk into `buffer`.
    ///
    /// This function places a command in `command_slot_index`, signals it to the port,
    /// and waits for an interruption indicating its completion.
    ///
    /// Based on `supports_48_bits_addresses`, this function will either use the
    /// `READ DMA` or `READ DMA EXT` command.
    ///
    /// # Unsafety
    ///
    /// * `buffer` must point to valid memory.
    /// * `buffer_len` must reflect `buffer`'s length.
    /// * `buffer[0] - buffer[buffer_len - 1]` must fall in a single mapping.
    /// * `command_slot_index` must be free to use, implemented,
    ///    and must point to `command_header` and `command_table`.
    /// * `px` must be properly initialized.
    ///
    /// # Error
    ///
    /// * `buffer_len` < `sector_count * 512`.
    /// * `sector_count` == 0.
    /// * `sector_count` is greater than supported maximum (256 for 28-bit devices, 65536 for 48-bit ones).
    /// * `lba + sector_count` is not representable on a 28-bit/48-bit address.
    /// * query_physical_address() failed.
    /// * AhciError::BufferTooScattered: `buffer` is so scattered it overflows PRDT.
    #[allow(clippy::too_many_arguments)] // heh
    #[allow(clippy::missing_docs_in_private_items)]
    pub unsafe fn read_dma(
        buffer: *mut u8,
        buffer_len: usize,
        lba: u64,
        sector_count: u64,
        px: &mut Px,
        command_header: &mut CmdHeader,
        command_table: &mut CmdTable,
        command_slot_index: usize,
        supports_48_bit: bool) -> Result<(), Error> {

        const ATA_CMD_READ_DMA:     u8 = 0xC8;
        const ATA_CMD_READ_DMA_EXT: u8 = 0x25;

        if sector_count.checked_mul(512).filter(|sec_size| *sec_size <= (buffer_len as u64)).is_none() {
            return Err(AhciError::InvalidArg.into())
        }
        if sector_count == 0 || (!supports_48_bit && sector_count > 256) || sector_count > 65536 {
            return Err(AhciError::InvalidArg.into())
        }
        if (!supports_48_bit && lba.saturating_add(sector_count) >= (1u64 << 28))
            || lba.saturating_add(sector_count) >= (1u64 << 48) {
            return Err(AhciError::InvalidArg.into())
        }
        // write the FIS
        let fis = &mut command_table.cfis.h2d;
        fis.fis_type.write(FisType::RegH2D as u8);
        fis.pm.write(1 << 7); // this is an update of the Command register
        if !supports_48_bit {
            // 28 bits
            fis.command.write(ATA_CMD_READ_DMA);
            fis.countl.write(sector_count as u8); // 0x00 means 256 sectors
            fis.counth.write(0);
            fis.lba0.write(lba as u8);
            fis.lba1.write((lba >> 8) as u8);
            fis.lba2.write((lba >> 16) as u8);
            fis.lba3.write(0);
            fis.lba4.write(0);
            fis.lba5.write(0);
            fis.device.write((1 << 6) | ((lba >> 24) as u8));
        } else {
            // 48 bits
            fis.command.write(ATA_CMD_READ_DMA_EXT);
            fis.countl.write(sector_count as u8); // 0000h means 65536 sectors
            fis.counth.write((sector_count << 8) as u8);
            fis.lba0.write(lba as u8);
            fis.lba1.write((lba >> 8) as u8);
            fis.lba2.write((lba >> 16) as u8);
            fis.lba3.write((lba >> 24) as u8);
            fis.lba4.write((lba >> 32) as u8);
            fis.lba5.write((lba >> 40) as u8);
            fis.device.write(1u8 << 6);
        };

        // fill the prdt
        unsafe {
            // safe: we have the same contract.
            command_table.fill_prdt(buffer, buffer_len, command_header)?
        }

        // fill the command header
        let mut ch_flags = CmdHeaderFlags(0);
        ch_flags.set_c(true);
        ch_flags.set_w(false);
        ch_flags.set_cfl((size_of::<FisRegH2D>() / 4) as u16);
        command_header.flags.write(ch_flags);

        // set PxCI
        px.ci.write(1u32 << command_slot_index);
        px.wait_command_completion(command_slot_index)?;
        Ok(())
    }

    /// Write `sector_count` contiguous sectors to the disk from `buffer`.
    ///
    /// This function places a command in `command_slot_index`, signals it to the port,
    /// and waits for an interruption indicating its completion.
    ///
    /// Based on `supports_48_bits_addresses`, this function will either use the
    /// `WRITE DMA` or `WRITE DMA EXT` command.
    ///
    /// # Unsafety
    ///
    /// * `buffer` must point to valid memory.
    /// * `buffer_len` must reflect `buffer`'s length.
    /// * `buffer[0] - buffer[buffer_len - 1]` must fall in a single mapping.
    /// * `command_slot_index` must be free to use, implemented,
    ///    and must point to `command_header` and `command_table`.
    /// * `px` must be properly initialized.
    ///
    /// # Error
    ///
    /// * `buffer_len` < `sector_count * 512`.
    /// * `sector_count` == 0.
    /// * `sector_count` is greater than supported maximum (256 for 28-bit devices, 65536 for 48-bit ones).
    /// * `lba + sector_count` is not representable on a 28-bit/48-bit address.
    /// * query_physical_address() failed.
    /// * AhciError::BufferTooScattered: `buffer` is so scattered it overflows PRDT.
    #[allow(clippy::too_many_arguments)] // heh
    #[allow(clippy::missing_docs_in_private_items)]
    pub unsafe fn write_dma(
        buffer: *mut u8,
        buffer_len: usize,
        lba: u64,
        sector_count: u64,
        px: &mut Px,
        command_header: &mut CmdHeader,
        command_table: &mut CmdTable,
        command_slot_index: usize,
        supports_48_bit: bool) -> Result<(), Error> {

        const ATA_CMD_WRITE_DMA:     u8 = 0xCA;
        const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;

        if sector_count.checked_mul(512).filter(|sec_size| *sec_size <= (buffer_len as u64)).is_none() {
            return Err(AhciError::InvalidArg.into())
        }
        if sector_count == 0 || (!supports_48_bit && sector_count > 256) || sector_count > 65536 {
            return Err(AhciError::InvalidArg.into())
        }
        if (!supports_48_bit && lba.saturating_add(sector_count) >= (1u64 << 28))
            || lba.saturating_add(sector_count) >= (1u64 << 48) {
            return Err(AhciError::InvalidArg.into())
        }
        // write the FIS
        let fis = &mut command_table.cfis.h2d;
        fis.fis_type.write(FisType::RegH2D as u8);
        fis.pm.write(1 << 7); // this is an update of the Command register
        if !supports_48_bit {
            // 28 bits
            fis.command.write(ATA_CMD_WRITE_DMA);
            fis.countl.write(sector_count as u8); // 0x00 means 256 sectors
            fis.counth.write(0);
            fis.lba0.write(lba as u8);
            fis.lba1.write((lba >> 8) as u8);
            fis.lba2.write((lba >> 16) as u8);
            fis.lba3.write(0);
            fis.lba4.write(0);
            fis.lba5.write(0);
            fis.device.write((1 << 6) | ((lba >> 24) as u8));
        } else {
            // 48 bits
            fis.command.write(ATA_CMD_WRITE_DMA_EXT);
            fis.countl.write(sector_count as u8); // 0000h means 65536 sectors
            fis.counth.write((sector_count << 8) as u8);
            fis.lba0.write(lba as u8);
            fis.lba1.write((lba >> 8) as u8);
            fis.lba2.write((lba >> 16) as u8);
            fis.lba3.write((lba >> 24) as u8);
            fis.lba4.write((lba >> 32) as u8);
            fis.lba5.write((lba >> 40) as u8);
            fis.device.write(1u8 << 6);
        };

        // fill the prdt
        unsafe {
            // safe: we have the same contract.
            command_table.fill_prdt(buffer, buffer_len, command_header)?
        }

        // fill the command header
        let mut ch_flags = CmdHeaderFlags(0);
        ch_flags.set_c(true);
        ch_flags.set_w(true);
        ch_flags.set_cfl((size_of::<FisRegH2D>() / 4) as u16);
        command_header.flags.write(ch_flags);

        // set PxCI
        px.ci.write(1u32 << command_slot_index);
        px.wait_command_completion(command_slot_index)?;
        Ok(())
    }
}

// Implementing Drop to do some clean-up is useless, we never hold a Px, always a reference to one,
// which never calls the drop method. Instead clean-up is the responsibility of the Disk owning the
// reference to an initialized Px.

// ---------------------------------------------------------------------------------------------- //
//                                         Command List                                           //
// ---------------------------------------------------------------------------------------------- //

/// Command Header. Pointed to by `PxCLB[i]`.
///
/// Indicates the PRDT length, and `Command Table` address and its FIS's length.
///
/// See section 4.2.2
#[repr(packed)]
#[allow(clippy::missing_docs_in_private_items)]
pub struct CmdHeader {
    // DW0
    flags: Mmio<CmdHeaderFlags>, /* Command FIS length in DWORDS, 2 ~ 16, atapi: 4, write - host to device: 2, prefetchable: 1 */
    prdtl: Mmio<u16>, // Physical region descriptor table length in entries
    // DW1
    prdbc: Mmio<u32>, // Physical region descriptor byte count transferred
    // DW2, 3
    ctba:  Mmio<u64>, // Command table descriptor base address
    // DW4 - 7
    _rsv1: [Mmio<u32>; 4], // Reserved
}

impl Debug for CmdHeader {
    /// Debug does not access reserved registers.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("HbaCmdHeader")
            .field("flags", &self.flags)
            .field("prdtl", &self.prdtl)
            .field("prdbc", &self.prdbc)
            .field("ctba", &self.ctba)
            .finish()
    }
}

bitfield!{
    /// Command Header word 0.
    ///
    /// Defined in section 4.2.2
    #[derive(Clone, Copy)]
    pub struct CmdHeaderFlags(u16);
    impl Debug;
    pmp,     set_pmp: 15,12; // Port Multiplier Port
    // 11 reserved
    c,         set_c: 10;    // Clear Busy upon R_OK
    b,         set_b:  9;    // BIST
    r,         set_r:  8;    // Reset
    p,         set_p:  7;    // Prefetchable
    w,         set_w:  6;    // Write. Indicates direction is a device write.
    a,         set_a:  5;    // Atapi. Indicates an ATAPI transfer.
    cfl,     set_cfl:  4,0;  // Command FIS Length.
}

/// The array of 32 [CmdHeader].
///
/// This struct is used to allocate the array of command slots used by the port.
///
/// Its physical address will be written in `PxCLB`.
// required alignment is 1024, coincidentally size is 1024,
// align(size_of(itself)) guarantees to prevent crossing page boundary.
#[repr(C, align(1024))]
#[allow(clippy::missing_docs_in_private_items)]
pub struct CmdHeaderArray {
    pub slots: [CmdHeader; 32]
}

assert_eq_size!(size_CmdHeaderArray; CmdHeaderArray, [u8; 1024]);

unsafe impl ZeroInitialized for CmdHeaderArray {}

impl CmdHeader {
    /// Initializes a CmdHeader, making it point to its [CmdTable].
    ///
    /// # Safety
    ///
    /// - `command_table` should not already be pointed to by any other CmdHeader.
    /// - port must not be running.
    pub unsafe fn init(&mut self, command_table: &mut CmdTable) {
        let phys_addr = virt_to_phys(command_table as _);
        self.ctba.write(phys_addr as u64);
    }
}

// ---------------------------------------------------------------------------------------------- //
//                                         Command Table                                          //
// ---------------------------------------------------------------------------------------------- //

/// Command Table.
///
/// Each entry in the command list points to a structure called the command table.
/// It can be found at `PxCLB[i].CTBA`.
///
/// See section 4.2.3
// required alignment is 128, but we use align(size_of(itself)) to prevent crossing page boundary.
#[repr(C, align(4096))]
#[allow(clippy::missing_docs_in_private_items)]
pub struct CmdTable {
    // 0x00
    cfis: Cfis, // Command FIS
    // 0x40
    acmd: [Mmio<u8>; 16], // ATAPI command, 12 or 16 bytes
    // 0x50
    _rsv: [Mmio<u8>; 48], // Reserved
    // 0x80
    prdt: [PrdtEntry; 248], // Physical region descriptor table entries, 0 ~ 65535.
                            // 248 entries fills the rest of the page.
}

assert_eq_size!(size_CmdTable; CmdTable, [u8; 4096]);

unsafe impl ZeroInitialized for CmdTable {}

/// Command FIS.
///
/// The FIS that will be sent to the device.
/// Bytes 0x00-0x40 of a [CmdTable].
#[allow(clippy::missing_docs_in_private_items)]
#[repr(C)]
union Cfis {
    raw_bytes: [Mmio<u8>; 64],
    h2d: FisRegH2D,
    // ...
}

assert_eq_size!(size_Cfis; Cfis, [u8; 64]);

/// Physical Region Descriptor Table entry.
///
/// Used for DMAs. A physical region is represented as a physical address and its length.
/// The `PRDT` is just a list of regions, which will be filled by AHCI's scatter-gather algorithm.
///
/// See section 4.2.3.3
#[allow(clippy::missing_docs_in_private_items)]
#[repr(packed)]
struct PrdtEntry {
    dba:   Mmio<u64>, // Data base address
    _rsv0: Mmio<u32>, // Reserved
    dbc:   Mmio<u32>, // Byte count, 4M max, interrupt = 1
}

impl Debug for PrdtEntry {
    /// Debug does not access reserved registers.
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("PrdtEntry")
            .field("dba", &self.dba)
            .field("dbc", &self.dbc)
            .finish()
    }
}


impl CmdTable {
    /// Fills a PRDT with the given buffer.
    ///
    /// The buffer can be physically scattered, this function will query all its physical regions
    /// from the kernel.
    ///
    /// When finished, this function will update the PRDTL count in `header`.
    ///
    /// # Unsafety
    ///
    /// * `buffer` must point to valid memory.
    /// * `buffer[0] - buffer[len - 1]` must fall in a single mapping.
    ///
    /// # Error
    ///
    /// * AhciError::BufferTooScattered: `buffer` is so scattered it overflows PRDT.
    /// * query_physical_address() failed.
    ///
    /// # Panics
    ///
    /// * length must be even.
    /// * `buffer[0]` must be the very start of the mapping.
    pub unsafe fn fill_prdt(&mut self, buffer: *mut u8, mut length: usize, header: &mut CmdHeader) -> Result<(), Error> {
        assert_eq!(length % 2, 0, "fill_prdt: length is odd.");
        assert_eq!(buffer as usize % 2, 0, "fill_prdt: buffer is not word aligned.");
        let mut index = 0;
        while length > 0 {
            let (mut phys_addr, _, mut phys_len, phys_off) = query_physical_address(buffer as _)?;
            phys_addr += phys_off;
            phys_len -= phys_off;
            // divide into 4M regions.
            // Range iterator has no .chunks() T.T
            while phys_len > 0 && length > 0 {
                let entry = self.prdt.get_mut(index)
                    .ok_or(AhciError::BufferTooScattered)?;
                // if buffer has spare space, ignore it.
                let region_len = min(min(phys_len, 0x400000), length);

                entry.dba.write(phys_addr as u64);
                entry.dbc.write((region_len - 1) as u32);

                phys_len -= region_len;
                phys_addr += region_len;
                index += 1;
                // also decrement total length.
                length -= region_len;
            }
        }
        // Interrupt on Completion on the last PRDT entry
        //self.prdt[index - 1].dbc.writef(1u32 << 31, true);
        header.prdtl.write(index as u16);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------- //
//                                         Received FIS                                           //
// ---------------------------------------------------------------------------------------------- //

/// Received FIS Structure. Pointed to by `PxFB`.
///
/// FIS received by the port will be copied to this structure, in the corresponding field.
///
/// See section 4.2.1
#[allow(clippy::missing_docs_in_private_items)]
#[repr(C, align(256))]
pub struct ReceivedFis {
    dsfis:  FisDmaSetup,
    _rsv0:  [u8; 4],
    psfis:  FisPioSetup,
    _rsv1:  [u8; 12],
    rfis:   FisRegD2H,
    _rsv2:  [u8; 4],
    sdbfis: FisSetDeviceBits,
    ufis:   [Mmio<u8>; 0x40],
    _rsv3:  [u8; 0x60],
}

assert_eq_size!(size_ReceivedFis; ReceivedFis, [u8; 0x100]);

unsafe impl ZeroInitialized for ReceivedFis {}

impl ReceivedFis {
    /// Return a const reference to the last received DMA Setup FIS.
    pub fn dsfis(&self) -> &FisDmaSetup {
        &self.dsfis
    }

    /// Return a const reference to the last received PIO Setup FIS.
    pub fn psfis(&self) -> &FisPioSetup {
        &self.psfis
    }

    /// Return a const reference to the last received D2H Register FIS.
    pub fn rfis(&self) -> &FisRegD2H {
        &self.rfis
    }

    /// Return a const reference to the last received Set Device Bits FIS.
    pub fn sdbfis(&self) -> &FisSetDeviceBits {
        &self.sdbfis
    }

    /// Return a const reference to the last received Unknown FIS.
    pub fn ufis(&self) -> &[Mmio<u8>; 0x40] {
        &self.ufis
    }
}
