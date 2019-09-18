# SunriseOS Security Architecture

SunriseOS aims to be a secure operating system with a strong threat model
preventing common classes of attack. Because it is based on Nintendo's
Horizon/NX operating system, we'll first review their threat model and security
architecture, and then we'll look at how to tweak it to fit our needs, which are
more user-centric.

## HOS/NX Threat Model

When designing the Nintendo Switch, Nintendo had multiple threats in mind:
pirates and online cheaters/modders. This means the threat in their model is the
user: it has physical access to the console, and their threat's goal is to
extract game content, and potentially tamper with it. It is therefore important
that the origin of the code running on the device is verified.

The above only applies to retail switches however. Nintendo obviously wants to
allow devkit users to load their own code on devkit units, without having to
manually verify them all the time. However, there too, it is necessary to limit
what devkit developers can do: they should only have access to the services and
APIs that games are allowed to use. This is both to increase the "security by
obscurity" aspect of the console, and to prevent the developer using APIs
intended only for internal use and subject to change at any notice.

Additionally, it is desirable to prevent downgrade attacks on the device. If a
vulnerability is found on an old version of the software, the user might try to
install that old version to gain better privileges. This should be made
impossible.

## HOS/NX Security Arch

Note: I'm going to be glossing over several details here. The idea is to get an
overview of all the security in place so we can reproduce them. If you need an
accurate description of the security, refer to [switchbrew wiki].

Obviously, I'm going to explain how things are *supposed* to work. Bugs were
found, security was broken, but the core architecture itself hasn't been
defeated! Only the specific implementation of HOS/NX sitting on top of the
Tegra X1 was.

### Encryption

The first step to securing the HOS/NX architecture is to ensure that absolutely
everything is encrypted. The user shouldn't be able to just dump the NAND and
get the games in clear. Furthermore, the encryption keys should be hidden in
such a way that accessing them physically is extremely costly, and preferably
in a way that prevents extracting them from the software side (e.g. a TPM).

The Tegra X1 on which the Switch is based sports a "Security Engine", basically
a TPM allowing loading keys into keyslots, and then encrypting/decrypting with
those without letting them leak. This engine is only directly usable from the
context of the TrustZone (which we'll review shortly), and is heavily used
everywhere crypto is involved.

Nintendo uses multiple layers of encryption to fulfill their needs. First, all
the important partitions are encrypted using full-disk encryption, with keys
living in the security engine. All executable content lives inside an NCA, a
sort of container format containing the code, permissions, and an embedded
filesystem. It is also fully encrypted. Finally, boot partitions are typically
encrypted as well. The only plaintext components of a NAND are the GPT headers
and a very small stub of the early boot partition (package1) that's responsible
for decrypting the rest of the early boot partition, and the BCT.

Thus, the user won't gain anything important from dumping their NAND.

### Boot Flow

When the user first turns on their Nintendo Switch, the Tegra X1's BootROM will
start executing. This is a firmware binary embedded in the SoC, which cannot get
modified after the device gets out of factory. The BootROM has one main job:
find the next stage to boot, verify its signature, load it and pass control to
it. It does so by parsing the [Boot Configuration Table (BCT)] from the NAND.
The BootROM will ensure that the pubkey modulus found in the BCT matches a hash
stored in the fuses embedded in the SoC, and that the signature matches.

The entry found in the BCT will cause the [Package1] to get loaded. Package1
contains the first stage bootloader (Package1Ldr), the second stage bootloader
(NX-Bootloader), The Secure Monitor firmware and the Warmboot firmware (used
instead of NX-Bootloader to wake up from sleep). Package1Ldr will do a very
minimal amount of hardware initialization, check the current version fuse to
prevent downgrade attacks, and finally derives a key using console unique
keydata that will be used to decrypt NX-Bottloader, "clear" the keys used to
derive the package1key, and finally pass control to it.

NX-Bootloader will load the SecureMonitor in the TrustZone, which will
be responsible for providing the kernel and userspace access to the TPM in a
safe way. It then loads the [Package2], which contains the kernel and kernel
modules. After decrypting and verifying the signatures, the kernel will be
loaded, and execution will be passed to it. The kernel will start running the
modules: boot, FS, Loader, NCM, ProcessMana, sm and spl.

From this point, all signature checking and sigcheck operations are done by FS.
It's the last component in the chain of trust. When Loader attempts to start a
process, it will ask FS to load the NCA's code section. FS will verify that the
NCA signature matches, then open the [NPDM] file and ensure the ACID signature
matches there. Finally, it will verify the NCA again, this time against the
secondary NCA signature.

### Permission checks

Every process in the Switch comes with a list of permissions limiting what it
can and cannot do. For KIP, those permissions live directly inside the
executable and only limit apply kernel limits - KIPs have full service and
filesystem access, but only limited syscalls are available. Those are protected
from tampering by virtue of being stored in the package2, which is signed.

For normal processes, the permissions are stored separately, in an [NPDM] file.
Those are stored inside the NCA, next to the binaries. There are three sets of
permissions: Kernel Capabilities, Service Accesses, and File System Permissions.

Kernel Capabilities are parsed by the Loader and configures how much access and
how many resources the process has access to. For instance, it configures which
syscalls the process can use, how many handles it can create, and whether it
can debug other applications, among other things.

Service Accesses are parsed by Service Manager (sm). It limits which
services the process can connect to, and which services the process is allowed
to register.

File System Permissions are parsed by the File System, and limits which
filesystems may be opened by the process. It's worth noting that the Switch has
no notion of file-level permissions. Instead, a whole "filesystem" can be given
access to or not. This is handled at the fsp-srv layer. For instance, a process
could be allowed to access the SD Card, or its own save filesystem, or other
applications' save filesystem, etc...

Thus, applications only have access to what they need, limiting the privileges
gained on successful exploitation. Those permissions are further sigcheck's by
both the Vendor (through the ACID and NCA signature) and the Developer (through
the NCA signature).

### W^X, ASLR, KASLR, IOMMU, disabled debugging extension

The Nintendo Switch OS employs multiple different technologies in order to
prevent or mitigate exploitation. Those include having a strict write xor
executable mapping policy (the kernel prevents mapping RWX pages at a very deep
level), full Address Space Layout Randomization for both the userspace and the
kernel, use of an IOMMU to prevent abusing device's ability to DMA to write to
sensitive memory.

To further secure the retail devices (which are the most security sensitive),
Nintendo went to great lengths to remove various debugging aids entirely:
various debugging SVCs are disabled in debug configurations, Userspace Exception
Handling is disabled, and various syscalls are stubbed out.

## SunriseOS

Now that we've got a good overview of how Nintendo does things, let's see how we
can adapt this for SunriseOS/x86. We'll first take a quick look at our threat
model, as it differs significantly from Nintendo's. Then we'll look at how we
can tweak their architecture to fit our needs.

### Threat model

TODO: Write our threat models. Will require careful planning.


[Boot Configuration Table (BCT)]: https://switchbrew.org/wiki/BCT
[Package1]: https://switchbrew.org/wiki/Package1
[Package2]: https://switchbrew.org/wiki/Package2
[switchbrew wiki]: https://switchbrew.org/
[NPDM]: http://switchbrew.org/index.php?title=NPDM