                                                                   Confidential, Attestable, and Efficient Inter-CVM
                                                                           Communication with Arm CCA

                                                        Sina Abdollahi∗ , Amir Al Sadi∗ , Marios Kogias∗ , David Kotz†‡ , Hamed Haddadi∗
                                                                             ∗
                                                                             Imperial College London, London, United Kingdom
                                                                       {s.abdollahi22, a.al-sadi, m.kogias, h.haddadi}@imperial.ac.uk
                                                                                  †
                                                                                    Dartmouth College, Hanover, NH, USA
                                                                                        David.F.Kotz@dartmouth.edu


                                        Abstract—Confidential Virtual Machines (CVMs) are in-                and data even against a compromised operating system
                                        creasingly adopted to protect sensitive workloads from priv-         or hypervisor, TEEs enable developers to deploy sensitive
arXiv:2512.01594v2 [cs.CR] 2 Dec 2025




                                        ileged adversaries such as the hypervisor. While they pro-           applications on untrusted infrastructure.
                                        vide strong isolation guarantees, existing CVM architectures             Although initially the TEE landscape was rather het-
                                        lack first-class mechanisms for inter-CVM data sharing due           erogeneous with different vendors offering different mech-
                                        to their disjoint memory model, making inter-CVM data                anisms, e.g., Intel providing enclaves with SGX [1] and
                                        exchange a performance bottleneck in compartmentalized               Arm offering physical memory partitioning with Trust-
                                        or collaborative multi-CVM systems. Under this model, a              Zone [2], over the years there is a convergence towards
                                        CVM’s accessible memory is either shared with the hy-                confidential virtual machines (CVMs) as the prevalent
                                        pervisor or protected from both the hypervisor and all               abstraction for confidential computing. Currently, major
                                        other CVMs. This design simplifies reasoning about memory            vendors have developed CVM offerings. Technologies
                                        ownership; however, it fundamentally precludes plaintext             such as AMD SEV-SNP (Secure Encrypted Virtualization-
                                        data sharing between CVMs because all inter-CVM com-                 Secure Nested Paging) [3] and Intel TDX (Trust Do-
                                        munication must pass through hypervisor-accessible mem-              main Extensions) [4] have already been adopted by cloud
                                        ory, requiring costly encryption and decryption to preserve          providers [5]–[9], while Arm has similarly introduced
                                        confidentiality and integrity.                                       Confidential Compute Architecture (CCA) [10], [11],
                                                                                                             which is expected to be deployed across both edge devices
                                            In this paper, we introduce CAEC, a system that enables
                                                                                                             and cloud servers.
                                        protected memory sharing between CVMs. CAEC builds
                                                                                                                 Despite design variations across vendors, all existing
                                        on Arm Confidential Compute Architecture (CCA) and
                                                                                                             CVM architectures adopt a disjoint memory model, in
                                        extends its firmware to support Confidential Shared Memory
                                                                                                             which each CVM owns a protected memory isolated from
                                        (CSM), a memory region securely shared between multiple
                                                                                                             both the hypervisor and other CVMs [3], [4], [11]. While
                                        CVMs while remaining inaccessible to the hypervisor and all
                                                                                                             each CVM may share memory with the hypervisor (e.g.,
                                        non-participating CVMs. CAEC’s design is fully compatible            for I/O), it cannot create protected memory regions shared
                                        with CCA hardware and introduces only a modest increase              with other CVMs only and not visible to the hypervisor.
                                        (4%) in CCA firmware code size. CAEC delivers substantial            This design simplifies reasoning about memory ownership
                                        performance benefits across a range of workloads. For in-            and provides strong confidentiality and integrity guaran-
                                        stance, inter-CVM communication over CAEC achieves up to             tees for the CVM’s protected memory region.
                                        209× reduction in CPU cycles compared to encryption-based                Such a disjoint memory model though, leads to sub-
                                        mechanisms over hypervisor-accessible shared memory. By              stantial efficiency losses in CVMs. In practice, this design
                                        combining high performance, strong isolation guarantees,             forces all inter-CVM communication to be exposed to the
                                        and attestable sharing semantics, CAEC provides a practical          hypervisor, either through hypervisor-managed services
                                        and scalable foundation for the next generation of trusted           such as virtual sockets (mode (a) in Fig. 1) or through
                                        multi-CVM services across both edge and cloud environ-               hypervisor-accessible shared memory regions (mode (b) in
                                        ments.                                                               Fig. 1). Both approaches require expensive encryption and
                                                                                                             decryption on the CVM sides to preserve confidentiality
                                        Index Terms—Confidential Computing, Arm CCA, Trusted
                                                                                                             and integrity when data is transmitted through hypervisor-
                                        Execution Environment, Attestation                                   accessible memory, while the use of confidential par-
                                                                                                             avirtual devices is an open challenge both in terms of
                                        1. Introduction                                                      performance and correctness [12]–[15]. Furthermore, the
                                                                                                             disjoint memory model prevents memory savings through
                                            Trusted Execution Environments (TEEs) have emerged               deduplication, where identical pages are shared across
                                        as a cornerstone for building secure systems in the pres-            CVMs. This inefficiency becomes particularly problematic
                                        ence of powerful adversaries. By providing isolated exe-             not only in large-scale datacenter environments where
                                        cution, integrity guarantees, and confidentiality for code           DRAM is a major cost factor, but also in memory-
                                                                                                             constrained edge and embedded devices, where TEEs are
                                        ‡ This work was performed while Professor Kotz was in residence at   increasingly deployed.
                                        Imperial College London.                                                 Unfortunately, communication and memory inefficien-
              CVM                         CVM                  CVM                             CVM           CVM                         CVM
    1                               3                      1                         2                  1                        2


                               Hypervisor-Mediated
                        2.a      Communication
                                                                     Hypervisor's Accessible
                                                                                                                Confidential Shared Memory
                                                                        Shared Memory

                         Hypervisor                  2.b                 Hypervisor                                   Hypervisor
    Plaintext Massage

                              (a)                                             (b)                                          (c)
    Encypted Massage




Figure 1: Communication modes between two CVMs. (a) Communication through virtualization services, where data
must be encrypted and passed via the hypervisor-mediated service. (b) Communication using shared memory provided
by the hypervisor, still requiring encryption as the shared memory is accessible to the hypervisor. (c) CAEC, which
enables CSM between CVMs. There is no need for encryption as CAEC protects the CSM from hypervisor and other
CVMs. Cyan: memory regions accessible to the first CVM, Green: memory regions accessible to the second CVM,
Purple: memory regions accessible to the hypervisor.


cies substantially affect modern machine learning (ML)                           limitations in the underlying isolation technology (risc-
and agentic systems, which increasingly dominate confi-                          v’s Physical Memory Protection), thus, restricting both the
dential computing workloads [5]–[9]. These systems are                           number of coexisting enclaves and the number of shared
increasingly becoming compartmentalized across CVMs,                             regions.
for example, splitting the networking and inference stacks                           Even after extending a confidential computing archi-
into different components to reduce the attack surface [5],                      tecture to support CSM across multiple CVMs, protecting
[6], [16]. Moreover, ML and agentic systems provide large                        the shared memory from attacks by other CVMs remains
opportunities for memory deduplication and sharing be-                           challenging. Participating CVMs must be able to discover
tween CVMs given the overlap in the models and contexts                          and attest each other while being assured that the shared
used across different applications, which can be multiple                        region cannot be accessed or modified by unauthorized
gigabytes.                                                                       CVMs. Without a principled ownership model and explicit
    To address this limitation, in this paper, we intro-                         access-control mechanisms, the system risks undermin-
duce Confidential Shared Memory (CSM), a hypervisor-                             ing the confidentiality of the CSM, enabling adversarial
protected (confidential) memory which can be shared                              CVMs to exploit the CSM management interface to esca-
between multiple CVMs. Designing a system that (1)                               late their privileges or gain unauthorized access to shared
enables CSM regions within a confidential computing                              regions.
environment and (2) restricts their use exclusively to                           Contribution. In this paper, we introduce CAEC, a sys-
mutually attested realms provides CVMs with a protected                          tem that enables CSM between CVMs in Arm CCA. To
memory for exchanging plaintext data directly with each                          the best of our knowledge, CAEC is the first approach
other (mode (c) in Fig. 1). This capability substantially                        to support CSM between CVMs. CAEC leverages Arm
improves CPU efficiency and memory utilization of inter-                         CCA’s RISC architecture to enable CSM without requir-
CVM data exchange.                                                               ing any modifications to the CCA hardware. It provides
    Enabling CSM may appear straightforward, yet it is a                         dynamically manageable memory sharing between CVMs
challenging undertaking. Depending on the architecture,                          without imposing any limitation on the number of shared
it may be infeasible without hardware modifications, for                         regions, either per CVM or system-wide. Through these
example, in AMD SEV-SNP (Section 8.2). Even systems                              capabilities, CAEC enables efficient plaintext communi-
that enable similar memory sharing between enclaves                              cation and the direct sharing of large resources (e.g.,,
(user-space TEEs) fail to provide flexible and scalable                          ML models) between mutually attested CVMs. We im-
mechanisms that fit the needs of modern ML systems. For                          plement CAEC on the latest functional and performance
instance, Plug-In Enclaves [17] enable read-only shared                          prototypes of Arm CCA. Our evaluation shows that CAEC
enclaves, which can be used to effectively share static                          achieves substantial performance improvements in inter-
resources such as libraries in serverless applications. Cer-                     CVM communication and memory sharing such as up to
berus [18] introduces formal techniques to verify such                           209× reduction in CPU cycles during communication. In
a sharing with the same read-only access model. How-                             summary, we claim the following contributions:
ever, both designs are insufficient for applications that re-                        •   CAEC extends the CCA firmware to support the
quire extensive inter-process communication (IPC), where                                 CSM. It introduces a principled ownership model,
writes must be visible to the other side. Elasticlave [19],                              explicit access-control rules, and attestation exten-
on the other hand, supports writable shared memory using                                 sions that ensure CSM remains protected from the
RISC-V Physical Memory Protection (PMP). However,                                        hypervisor and all unauthorized CVMs. Our analysis
the underlying isolation mechanism inherently limits the                                 shows that CAEC prevents unauthorized access to
number of shareable regions: the total number of mem-                                    CSM while preserving CCA’s security guarantees for
ory partitions (protected or shared) (e.g., to 16) due to                                all non-CSM regions.
TABLE 1: Memory access control applied by Granule                                      (GPT). A hardware mechanism called Granule Protection
Protection Check (GPC) in CCA                                                          Check (GPC) enforces access restrictions based on both
 Security State         Normal PAS         Secure PAS      Realm PAS        Root PAS   the ownership state of each granule (as recorded in the
 Normal                     ✓                   ✗              ✗               ✗       GPT) and the current processor state. A memory access
 Secure                     ✓                  ✓               ✗               ✗
 Realm                      ✓                   ✗              ✓               ✗       is permitted only if it complies with the rules defined in
 Root                       ✓                  ✓               ✓               ✓       Table 1. In particular, when the processor operates in the
                                                                                       root world state, it has access to the physical address space
                                                         NW VM
        Realm memory                                                                   (PAS) of all other worlds. When operating in the realm or
EL0
           RTT                                   App       App       App               secure world, the processor can access the normal world’s
           RTT
             RTT
             RTT
                                      Realm                                            PAS, but the realm and secure worlds are isolated from
                DATA            Memory VM
EL1
                                Layout           OS        OS        OS
                                                                              Secure   each other. The normal world has no access to the PAS of
                                                                               Stack
        Realm metadata                                                                 any other world. Arm CCA also leverages the isolation
                                    RSI
                                                                                       primitives of the Arm architecture—such as exception
       RTT
       RTT                   RTT
                             RTT
EL2     RTT     REC    RD     RTT         RMM           Hypervisor
         RTT                  RMM                                                      levels (ELs) and virtualization. Exception levels begin
                                    RMI
                                                                                       with EL3, the highest privilege level in the system, while
EL3                                                      Monitor                       EL2–EL0 provide intra-world privilege separation. The
               Realm World      Root World      Normal World          Secure World
                                                                                       architecture support for virtualization includes two stages
                                                                                       of address translation: mapping virtual addresses (VAs)
Figure 2: Arm CCA 1.0 software architecture. The hy-                                   to intermediate physical addresses2 (IPAs) and mapping
pervisor allocates resources (e.g., memory and CPU) for                                IPAs to physical addresses (PAs).
realm VM but cannot access those resources, as the realm                                   Within CCA, the architecture software stack includes
VM is running on the other side of the isolation bound-                                the Monitor running at EL3, responsible for initially boot-
aries.                                                                                 ing all EL2 components, managing GPTs, and context
                                                                                       switching between worlds. The normal world stack con-
                                                                                       sists of a hypervisor operating at EL2, virtual machines
   • CAEC integrates cleanly across all layers of the                                  (VMs) running at EL1 and EL0, and user-space apps
     CCA stack, providing flexible CSM management                                      running at EL0. Secure world can host a stack similar to
     capabilities to realms while retaining the hypervisor’s                           the NW, however, it is usually reserved for vendor specific
     authority over physical memory management. CAEC                                   services, impossible to run third party code. The realm
     achieves this with only a 4% increase in firmware                                 world stack consists of realm VMs (or simply realms) run-
     size.                                                                             ning at EL1 and EL0 and a lightweight firmware known
   • CAEC demonstrates significant benefit for commu-                                  as Realm Management Monitor (RMM). In CCA, the
     nication and data sharing between CVMs. CAEC                                      hypervisor retains control over system resources such as
     achieves up to a 209× reduction in CPU cy-                                        CPU cores and physical memory. It can allocate or reclaim
     cles compared to encryption-based mechanisms over                                 resources for realms much like it does for NW VMs.
     hypervisor-accessible shared memory. Moreover us-                                 However, in the case of realms, the RMM acts as a trusted
     ing CAEC, big data like a LLM can be shared                                       mediator between the hypervisor and realms. It validates
     between two CVMs, resulting in 16.6%–28.3% re-                                    all hypervisor requests concerning realm resources and
     duction in the system’s memory footprint.                                         proceeds only if they satisfy CCA’s isolation and security
                                                                                       requirements.
2. Background & Motivation
                                                                                       2.2. Realm Management Monitor
    In this section, we review the foundational concepts
required for the remainder of the paper. We begin with                                     The RMM is the trusted firmware component in CCA
an overview of Arm CCA (Section 2.1), followed by a                                    responsible for coordinating all interactions between the
discussion of two key components of the architecture:                                  hypervisor and realms. It enforces isolation by protecting
the Realm Management Monitor (Section 2.2) and the                                     resources delegated to realms from both the hypervisor
attestation framework (Section 2.3). We conclude this                                  and other realms, while maintaining the hypervisor’s ca-
section with the motivation behind this work (Section 2.4).                            pability to manage those resources. To achieve this, the
                                                                                       RMM exposes Realm Management Interface (RMI) to
2.1. Arm CCA                                                                           the hypervisor and the Realm Service Interface (RSI) to
                                                                                       realms [20]. The hypervisor can issue RMI commands to
    Arm CCA [10] is a series of hardware and software                                  request operations on realm resources such as memory
extensions for Armv9-A architecture (Fig. 2). Arm CCA                                  delegation or vCPU (virtual CPU) scheduling. However,
extends the Armv9-A architecture with realm world1 and                                 before executing these operations, the RMM performs a
root world, orthogonal to the existing normal world (NW)                               series of validity checks and proceeds only if all valida-
and secure world. Each 4 KB frame of physical memory                                   tions succeed. The RSI also can be used by realms to ac-
(also referred to as a granule) is tagged with the world it                            cess services such as attestation and hypercalls. The RMM
belongs to at any given time. This ownership information                               manages four types of granules during the lifecycle of
is recorded in a structure called Granule Protection Table                             each realm (Fig. 2): (1) the Realm Descriptor (RD), which

   1. In some references, the term execution environment is used instead                  2. We adopt Arm’s term intermediate physical address (IPA), which
of world; however, in this work, the two terms are used interchangeably.               is also commonly referred to as guest physical address (GPA).
defines the realm’s general attributes (e.g., address space
size); (2) the Realm Execution Context (REC), which                                                                                    Realm Owners
stores vCPU-related state (e.g., system registers); (3) the                                     Proprietary
Realm Translation Tables (RTTs), a hierarchical structure                                          Data

maintaining IPA-to-PA mappings and access permissions;
                                                                                Realm        Realm            Realm         Realm
and (4) DATA granules, which represent protected mem-                            VM           VM               VM            VM
ory regions accessible only to realm software.                                                                                              Host
    To allocate a new DATA granule to realm during                               Compartmentalized     Inter-realm      Realm-Host
runtime, the hypervisor must first delegate a granule to the                Realm    Service         Communication     Communication                  Normal
                                                                            World                    RMM                                              World
realm world using RMI_GRANULE_DELEGATE. It then
                                                                            Root
requests the RMM to create the corresponding mapping                        World
                                                                                                                   Monitor
in the realm’s protected address space3 using RMI_DATA
                                                                                    Root of Trust                     CPU                  Memory
_CREATE_UNKNOWN. Upon receiving the request, the
RMM verifies that the granule has already been delegated                                                      Computing Platform
to the realm world (i.e., inaccessible to the hypervisor)
and that it is not already mapped in the protected address                                   Figure 3: CAEC System Model
space of another realm, thereby enforcing CCA’s disjoint
memory model. After creating the new mapping in the
RTT, the granule becomes accessible to realm.                              Arm CCA for CSM. Arm CCA introduces architectural
                                                                           properties that make it a promising candidate for support-
2.3. Attestation                                                           ing flexible and secure CSM. First, unlike AMD SEV-
                                                                           SNP or Intel TDX, which rely extensively on hardware
                                                                           and microcode extensions, CCA places most of its trusted
    In CCA, a realm can obtain an attestation token via                    functionality in firmware (i.e., the RMM) while relying
RSI. The attestation token is a set of claim values and                    on a small set of hardware mechanisms to enforce isola-
their signature that describe the state of the realm and the               tion [24], [25]. This design provides better flexibility for
platform on which it runs [20], [21]. A token includes                     extending the architecture with new features. For example,
claims such as the Realm Initial Measurement (RIM),                        CCA uses the GPC hardware mechanism to isolate the
which captures the realm’s configuration and initial mem-                  realm world from the normal world, but isolation be-
ory contents. Because the RMM computes these claims                        tween realms is enforced entirely through RMM-managed
and signs them as part of the token, a remote verifier (e.g.,              checks. Because these checks reside in firmware rather
a realm owner) can (1) validate their authenticity, ensuring               than hardware, they can be extended or relaxed through
that each claim was generated by the trusted RMM and                       firmware updates. Similarly, the RMM can incorporate
has not been tampered with and (2) check whether these                     new metadata types and validation rules without requiring
claims match the expected values.                                          hardware or microcode modifications—capabilities that
                                                                           are essential for securely managing CSM regions across
2.4. Motivation                                                            realms. Second, in contrast to the physical partitioning
                                                                           mechanism used in Elasticlave [19], CCA’s use of virtu-
     The traditional disjoint memory model of CVMs for-                    alization can be adapted to support an unbounded number
bids any form of CSM between CVMs. This design is rea-                     of regions, both within a single CVM and across the
sonable under the common assumption that CVMs do not                       system, albeit with increased design complexity. Overall,
trust one another. However, it is too restrictive for emerg-               these properties suggest that CCA provides a solid foun-
ing workloads, which increasingly require CVMs—while                       dation for implementing a scalable and fine-grained CSM
still isolated from each other—to collaborate once attes-                  mechanism within a confidential computing architecture.
tation confirms that a peer is running an expected and
acceptable software stack. These collaborating CVMs may                    3. System & Threat Model
belong to different administrative parties (e.g., agentic
systems [22] or collaborative learning [23]), or they may                     In this section, we present system model (Section 3.1)
belong to a single organization but be compartmentalized                   and threat model (Section 3.2) of CAEC.
for security (e.g., separating networking and inference
stack [6]). Under the current trust model, such workloads                  3.1. System Model
cannot efficiently exchange plaintext data or share large
identical memory regions (e.g., LLM model weights),
                                                                                CAEC’s system model is illustrated in Fig. 3. CAEC
even though the shared content itself poses no confiden-
                                                                           is designed to operate across both edge platforms (e.g.,
tiality risk. Meeting these emerging demands requires re-
                                                                           smartphones) and cloud platforms that support the Armv9-
thinking the architecture of confidential computing: CVMs
                                                                           A architecture with CCA extensions. The platform boots
must be able to share CSM with attested peers while
                                                                           the CCA firmware, consisting of the RMM and the Mon-
remaining fully protected from untrusted or malicious
                                                                           itor, along with a hypervisor responsible for managing
CVMs.
                                                                           system resources. The hypervisor and all services run-
  3. A realm’s address space consists of two halves: the protected half,
                                                                           ning under its control are collectively referred to as the
used to map realm-world granules, and the unprotected half, used to map    host. Realm owners are entities external to the computing
normal-world granules.                                                     platform that provide confidential services, either locally
(when the platform is an edge device) or remotely (in           identifier (Section 4.3) and physical memory management
the cloud scenario). Examples of such services include          (Section 4.4).
model inference [26]–[28], private LLM agents [14], [22],
digital rights management (DRM), and authentication ser-        4.1. Realm Setup
vices [29]. Realm owners are mutually untrusted with
respect to one another and to the host; each seeks to               At a high level, CAEC extends Arm CCA with support
protect its proprietary data from all other entities. Realm     for CSM, enabling realms to securely create, manage, and
owners deploy realm(s) to deliver their services while pre-     attach to CSM regions. The RMM serves as the trusted
serving the confidentiality of their proprietary data from      core of CAEC: it implements validation, enforces ac-
other entities. A single realm owner may further com-           cess control, and orchestrates all CSM-related operations.
partmentalize its service into multiple realms for stronger     CAEC introduces new RSI commands to the RMM, which
isolation. Realm owners may agree to collaborate and            exposes the CSM-related services to realms (see Table 2).
share data only through attested realms and explicitly
                                                                Ownership Model. in CAEC each CSM region has ex-
established CSM regions between those attested realms.
                                                                actly one creator and lifetime manager, referred to as its
The use of realms to deliver confidential services and
                                                                Provider realm (P-realm). The P-realm (1) contributes a
host proprietary data of external entities (realm owners)
                                                                portion of its protected address space to instantiate the
adhere to the design principle of CCA [10], [30] and align
                                                                CSM region, (2) grants or revokes other realms’ access
with other system models such as Android Virtualization
                                                                to it, and (3) determines the access permissions types
Framework [31] and ASTER [32]. CAEC assumes that
                                                                (e.g., read-only or read-write) of each participating realm.
all entities in the system trust the device’s hardware and
                                                                Realms that later join an existing CSM region are referred
the CCA firmware. Finally, the hypervisor is assumed to
                                                                to as Consumer realms (C-realms). Crucially, these roles
provision the necessary resources (e.g., memory and CPU
                                                                are per-region and not global: a realm may act as a P-
time) to ensure forward progress of realms.
                                                                realm for some CSM regions and a C-realm for others.
3.2. Threat Model                                               Allocation Semantics. CAEC preserves the hypervisor’s
                                                                control over physical memory management for both CSM
    Following the Arm CCA threat model [30], CAEC               and non-CSM regions, aligning with Arm CCA’s design
assumes that the host and all realms are mutually un-           principles. Since a CSM region is shared across multiple
trusted. For any given realm, both the host and other           realms, memory-management flows must diverge from
realms may attempt to compromise the confidentiality or         those used for regular private memory of realms. Accord-
integrity of its protected memory or vCPU state. This           ingly, the RMM notifies the hypervisor whenever CSM
includes collaborating realms, which may try to read            regions are created, shared, or removed (through vCPU
or modify memory outside the mutually agreed CSM                exits, see Table 2). The hypervisor uses this information to
boundaries. A realm may also attempt to obtain additional       populate the P-realm’s CSM region while ensuring that C-
resources (e.g., granules) beyond those delegated by the        realms do not receive additional physical granules beyond
host or retain resources longer than permitted, which may       what the P-realm explicitly shares (see Section 4.4 for
result in denial-of-service (DoS) attack against the host or    further details). CAEC, however, guarantees that once a
other realms. Introducing CSM support creates additional        CSM region is established, all participating realms observe
attack vectors. Because CAEC exposes CSM creation and           an identical and consistent view of the underlying physical
access to existing ones as a generic service available to       granules.
all realms (including malicious realms), an adversarial         Access Policy Table. The RMM in CAEC requires to
realm might attempt to impersonate an attested peer to          effectively track the state and ownership of each CSM
gain unauthorized access to an existing CSM. Conversely,        region. In particular, whenever a realm issues a CSM-
it may create a fake CSM region and trick other realms          related RSI command, the RMM must consult—and po-
into using it, thereby compromising the confidentiality or      tentially update—the corresponding metadata to ensure
integrity of shared data. Such an adversarial realm may         that all security checks are correctly enforced. In CCA,
belong to a competing realm owner or be instantiated            however, the RMM does not store per-realm metadata di-
by the host itself with the intent of targeting a specific      rectly in its internal memory; instead, it relies on metadata
CSM configuration. Physical attacks and microarchitec-          granules that the hypervisor delegates to each realm (e.g.,
tural side-channel attacks are out of scope. The platform       RTT granules). Following this design principle, CAEC
is assumed to support secure boot, ensuring the trusted         introduces a new metadata structure, Access Policy Table
loading and execution of all EL3 and EL2 components and         (APT), associated with each realm. The APT allows the
preventing boot-time compromise. Hardening of higher-           RMM to record metadata for all CSM regions mapped into
level protocols and interfaces used by realms for inter-        a realm’s protected address space. APT record one entry
CVM communication is considered orthogonal to CAEC’s            per CSM region, which is either P-realm entry or C-realm
contribution.                                                   entry (depending on the role of the realm in that CSM).
                                                                C-realm entries store information such as base address,
4. CAEC                                                         size, the identifier of the owner (P-realm), while P-realm
                                                                entries keep additional metadata such as permission type
    In this section, we introduce CAEC. We begin by             of C-realms authorized to access that CSM. To prevent
describing the setup of each realm in Section 4.1. We then      race conditions or deadlocks, CAEC reuses the RMM’s
present the full lifecycle of CSM in Section 4.2, and finally   existing locking mechanisms [33], ensuring that multiple
detail several key design components, including the realm       vCPUs cannot access or modify realm’s APT concurrently.
                                                    TABLE 2: New and modified commands introduced by CAEC
 Type                  Name                                                          Description
 Caller: Hypervisor Callee: RMM
 New RMI               err = RMI_APT_CREATE(PARD ,PAAPT )                            Allocates the granule at physical address PAAPT for the realm’s APT.
 New RMI               err = RMI_APT_DESTROY(PARD ,PAAPT )                           Destroys the realm’s APT. This command is only invoked during realm destruction.
 Modified RMI          err = RMI_DATA_CREATE_UNKNOWN(PARD ,PAD ,IPAD )               Maps a data granule D at physical address PAD into intermediate physical address IPAD .
                                                                                     CAEC ensures that if IPAD is in a CSM region, new mappings are created for other participating realms.
 Modified RMI          err = RMI_DATA_DESTROY(PARD ,IPAD )                           Wipes and unmaps the data granule in IPAD .
                                                                                     CAEC ensures that if IPAD is in a CSM region, it is unmapped for other participating realms.
 Caller: P-realm       Callee: RMM
 New RSI               IDCSM = RSI_CSM_CREATE(IPAbase-P ,SizeCSM )                   Creates a CSM region beginning at IPAbase-P with size SizeCSM . Returns CSM identifier IDCSM .
 New RSI               IDCSM-PC = RSI_CSM_SHARE(IDCSM ,IDC ,P)                       Shares a CSM region IDCSM with a C-realm identified by IDC and access permission P. Returns the sharing identifier IDCSM-PC .
 New RSI               err = RSI_CSM_REVOKE(IDCSM-PC )                               Revokes access to an already existing sharing identified by IDCSM-PC .
 New RSI               err = RSI_CSM_DESTROY(IDCSM )                                 Destroys a CSM region identified by IDCSM .
 Caller: C-realm       Callee: RMM
 New RSI               err = RSI_CSM_RESERVE(IDCSM-PC ,IPAbase-C ,SizeCSM )          Reserves a region begins at IPAbase-C with size SizeCSM for sharing identified by IDCSM-PC .
 New RSI               err = RSI_CSM_ATTACH(IDCSM-PC )                               Maps the CSM with sharing identifier IDCSM-PC into the corresponding reserved region, delegating access to the CSM.
 New RSI               err = RSI_CSM_DETACH_AND_FREE(IDCSM-PC )                      Unmaps the CSM with sharing identifier IDCSM-PC from the C-realm private address space and frees the previously reserved region.
 Caller: RMM           Callee: Hypervisor
 New Exit Reason       REC_EXIT_C_REALM_CSM(IPAbase-C ,SizeCSM )                     Notifies the hypervisor about a new CSM region in the C-realm’s protected address space.
 New Exit Reason       REC_EXIT_P_REALM_CSM(IPAbase-P ,SizeCSM )                     Notifies the hypervisor about a new CSM region in the P-realm’s protected address space.
 New Exit Reason       REC_EXIT_REALM_REMOVE_CSM(IPAbase-P ,SizeCSM )                Notifies the hypervisor to remove a CSM region from realm’s protected address space.

                                                  The physical address of RD PARD must be provided within each RMI command.


                                                                                                                                            3.1
                                                                     3.1
                                                                                                                                                  Peer Realm Attestation
                                            Peer Realm Attestation                                                                                                                            Realm Owners
                   1                                                                                                                                       1   Realm Attestation
                          Realm Attestation             3.2                                                                                                                                 3.2

  P-realm                2.7                                                                                    C-realm
                                   CSM                                                                                                            5.1
        2.1                                                                                                                                                                                                4.5
                                                         4.1
                                                                       4.4

        2.2                                                                  4.3                                                                                                                           4.6
                                               Validate Request
                                                                                                   APT   RMM          APT
                                                                                                                                                                                4.7
   Validate Request                                                    Extend CSM              P-Entry               C-Entry                                                                   Validate Request
                               CSM-backed               4.2               Entry                                                                                                 Add Entry
        2.3                                                                                                                     5.2
                                Memory                                                                                                           RTT
                                                                                         RTT               Find Entries and                    RTT                 CSM is now
           Add new CSM                                                                RTT                                                   RTT
                                                                                                                                           RTTIPA1 > PA1
                                                                       2.6          RTT
                                                                                   RTTIPA1 > PA1           Validate Sharing                                    accessible to C-Realm
            entry to APT             DATA          Create Mapping                                                                                 ...
                                    DATA
                                   DATA                                                   ...
                                                                                                          Find PAs              5.3
                                  DATA
                                                      in RTTs
                                                                                                         Create New Mappings                                   5.5   Clear Mapping in RTTs
           2.4                                                                                                                                                                                           4.8
                                       2.5                                                                     5.4                                                     4.9


    Populate Region                                                                                  Hypervisor                                                                 Undelegate Region's Granules


                                                                             Figure 4: Overview of CAEC.


Realm Initialization. CAEC adapts the realm initializa-                                                      satisfied, the RMM registers this region within the APT
tion flow of CCA, in which the hypervisor issues RMI                                                         of P-realm, notifies the hypervisor about the new CSM
commands [20] to populate the initial realm’s image and                                                      region via vCPU exit REC_EXIT_P_REALM_CSM. The
delegate realm’s metadata granules. The metadata gran-                                                       hypervisor then populate the entire CSM range within
ule introduced by CAEC (i.e., APT) is similarly created                                                      the P-realm’s private address space (see Section 4.4).
and initialized through a new RMI command, RMI_APT                                                           For every new delegated granule, the RMM creates the
_CREATE (see Table 2). At this stage, the APT is allo-                                                       corresponding entry in the P-realm’s RTTs. The RMM
cated for each realm within the RMM’s internal structures                                                    later returns a unique region identifier IDCSM to the realm
but does not yet contain any configuration. Once initial-                                                    (steps 2.1 to 2.7 in Fig. 4).
ization is complete, the hypervisor begins scheduling the
vCPUs of each realm. At this point, realms can communi-                                                      Pre-Sharing. Before sharing CSM, realms must be able to
cate with external entities, including their respective realm                                                securely identify their peers. To enable this, CAEC adapts
owners. The realms establish TLS channel and prove them                                                      the attestation primitives of CCA and delegates peer realm
self to their realm owner via attestation (step 1 in Fig. 4).                                                attestation to the realm owners. Each realm owner attests
                                                                                                             the peer realm to verify that the expected software stack is
                                                                                                             running within it (step 3.1 ). In CAEC, the RMM assigns
4.2. CSM Lifecycle                                                                                           each realm a unique identifier that is used to refer to
                                                                                                             that realm during subsequent CSM-related operations. The
Creation. A realm can create arbitrary CSM regions in its                                                    RMM also reports these identifiers as a separate claim
private address space via RSI_CSM_CREATE, providing                                                          in the attestation token. As a result, realm identifiers
the region’s start address and size (see Table 2). While                                                     can be reliably recovered by realm owners during peer
CAEC does not restrict the number of CSM regions a                                                           realm attestation. After validating the attestation report
realm may create, each region must (1) be granule-aligned                                                    (i.e., checking that realm’s claims match the expected
and (2) not overlap with any existing CSM region in                                                          values), realm owners distribute the validated peer realm’s
the realm’s private address space. If these conditions are                                                   identifier to their respective realms (step 3.2 ). From this
point onward, both realms know each others identifiers. In      can also destroy a CSM region via RSI_CSM_DESTROY
Section 4.3, we provide a detailed explanation on realm         with the region identifier provided. In return the RMM,
identifier and the way CAEC builds it.                          repeats the handler of RSI_CSM_REVOKE command for
Sharing. To allow sharing CSM between realms, CAEC              every peer C-realm and finally destroys the associated
adopts a simple but strong rule: a realm can attach to an       APT entry. The RMM then notifies the hypervisor about
existing CSM region only if both the P-realm and the C-         the destruction of CSM sharing in the P-realm’s private
realm explicitly agree to share and attach, respectively. P-    address space via REC_EXIT_REMOVE_CSM. The C-
realm can initiate sharing by issuing RSI_CSM_SHARE,            realm can also unmap and free its address space from
providing the region identifier IDCSM , the desired access      the CSM via RSI_DETACH_AND_FREE with the sharing
permissions P, and the identifier of the C-realm IDC . The      identifier provided. In return, the RMM remove mapping
RMM validates these inputs and, upon success, records a         from C-realm’s RTT, removes the associated entry in
sharing identifier in the P-realm’s APT entry associated        the APT of C-realm, and notifies the hypervisor about
to the CSM region, marking that the P-realm has agreed          the destruction of CSM sharing in the C-realm’s private
to share the CSM with the specified C-realm. It returns         address space via REC_EXIT_REMOVE_CSM.
the sharing identifier IDCSM-PC to the P-realm (steps 4.1 to
4.4 ). The identifier is a deterministic concatenation of the   4.3. Realm Identifier
P-realm and C-realm identifiers, combined with a counter
to distinguish multiple shared regions between the same              In the traditional model of CCA , all RMM services
pair of realms.                                                 (exposed as RSI and RMI commands) are local to a single
     On the C-realm side, it can regenerate the sharing         realm. By contrast, CAEC extends the RMM to support
identifier due to its deterministic format. The C-realm         services between realms, enabling realms to share CSM
must then reserve a region of identical size in its own         with one another. This fundamentally requires realms to
private address space using RSI_CSM_RESERVE. It pro-            identify and refer to each other securely. For example,
vides the region’s start address, size, and the region iden-    a realm invoking RSI_CSM_SHARE must specify the
tifier IDCSM to the RMM. The RMM verifies that the              identifier of the target C-realm. The RMM must be able
reserved range (1) is granule-aligned and (2) does not          to reliably interpret these identifiers to enforce access
overlap with any existing CSM region already present in         control throughout the CSM lifecycle. If realm identifiers
the C-realm’s address space. If the checks succeed, the         were forgeable or manipulable (e.g., by a malicious hy-
RMM adds a corresponding entry to the C-realm’s APT,            pervisor), the security of CAEC would be fundamentally
indicating that the C-realm has agreed to attach to the         compromised. Thus, CAEC requires a secure, unforgeable
region shared by the designated P-realm. The RMM then           mechanism for realm identification.
notifies the hypervisor via REC_EXIT_C_REALM_CSM,               CCA Identifier Model. The RMM design in CCA pro-
prompting the hypervisor to undelegate any previously           vides no such system-wide realm identifier, as the RMM
assigned granules in the reserved CSM range of the C-           was not designed to support inter-realm operations. The
realm (steps 4.5 to 4.9 ).                                      RMM in CCA distinguishes realms solely by the physical
Access. To gain access to the shared region, the C-realm        address of their RD, which the hypervisor supplies with
must finally issue RSI_CSM_ATTACH with the sharing              each RMI invocation. However, this identifier is unsuitable
identifier IDCSM-PC provided. The RMM first locates the         to be used as identifier between realms. First, exposing
corresponding entries in both the P-realm’s and the C-          RD physical addresses as the identifier to entities such
realm’s APTs; the presence of both entries confirms that        as realm owners and their associated realms meaning that
the P-realm has previously agreed to share the region and       they obtain information about the physical memory layout
the C-realm has agreed to attach. CAEC does not require         of the system, which violates virtualization principles.
the CSM region to appear at the same base IPA address in        Second, since the hypervisor can control physical memory
each realm’s private address space. However, both realms        layout, it provides no uniqueness guarantee: a malicious
must use an identical size for the region; this ensures that    hypervisor could terminate the current realm and instan-
neither realm gains unauthorized access to memory out-          tiate a malicious one at the same RD address, causing
side the mutually agreed-upon CSM boundaries. If these          both to appear to have the same identifier. This enables a
conditions are satisfied, the RMM begins constructing           classic time-of-check-to-time-of-use (TOCTOU) attack in
the required mappings in the C-realm’s address space.           which the hypervisor can replace a legitimate realm with
To achieve that, the RMM walks through the P-realm’s            a malicious one while preserving the same identifier. In
RTTs to locate the physical addresses corresponding to          summary, none of the realm-related arguments available in
the CSM’s range and creates equivalent mappings in the          the current CCA design satisfies both essential properties:
C-realm’s RTTs (steps 5.1 to 5.5 ). During this process, the    (1) not leaking system-level information, and (2) being
RMM applies the access permissions previously specified         protected from hypervisor manipulation. Candidates such
by the P-realm to all new RTT entries of C-realm. Once          as the RD physical address, the Realm Personalization
these mappings are established, the C-realm can access          Value (RPV), and the Virtual Machine ID (VMID) [20]
the CSM region according to the assigned permissions.           all fail to meet both criteria.
Revocation & Destruction. The P-realm retains its con-          Realm Identifier in CAEC. The RMM in CAEC assigns
trol over sharing of the CSM with the C-realm. It can           a unique system-wide identifier to each newly created
issue RSI_CSM_REVOKE, which removes the mapping                 realm and maintains a registry of these identifiers. These
from the C-realm’s RTT, and clear the C-realm’s identifier      identifiers reveal no information about the underlying
from the associate APT entry in P-realm APT. A P-realm          system and are safe from hypervisor manipulation, as
each realm receives a fresh identifier upon creation. The      or the secure world is strictly prohibited. Since the RMM
RMM further reports realm identifier as a separate claim       enforces that all CSM regions reside the realm world,
within each attestation token, creating a cryptographic        CSM regions are inherently protected from direct access
binding between the identifier and other claims—such as        attempts originating from normal world and secure world
the RIM—within the attestation token. As a result, the         actors.
realm identifier becomes an attestable property that third         CAEC defends the CSM against malicious realms
parties can verify alongside other claims. The attestation     through two complementary mechanisms: (1) A system-
token in CAEC can prove (1) the realm’s software and           wide, attestation-integrated realm identifier, and (2)
platform configuration (as in CCA), and (2) the authen-        RMM-enforced access control checks within all CSM-
ticity of the realm identifier (new in CAEC). Consequently,    related RSI commands. First, reporting realm’s identifier
realm owners can use attestation to obtain authenticated       as a separate claim in the attestation token creates a cryp-
identifiers of peer realms and safely distribute them to       tographic binding between realm identifier and its other
their own realms for subsequent CSM-related operations.        claims such as RIM. Realm owners verify these claims
                                                               and proceed only if they match the expected configuration,
4.4. Physical Memory Allocation                                after which they provision the validated identifier to their
                                                               associated realm. A malicious realm, whether instantiated
     When a new CSM region is registered, the                  by a competing realm owner or by the hypervisor, cannot
RMM notifies the hypervisor through the vCPU                   bypass this attestation check because its software content
exits REC_EXIT_P_REALM_CSM and REC_EXIT_C                      (and thus its RIM) will not match the expected values.
_REALM_CSM. These notifications allow the hypervisor           Consequently, such a realm cannot impersonate an attested
to finalize the physical memory configuration required for     peer, attach to an existing CSM, or create a fraudulent
subsequent system operations. If the request corresponds       CSM region to lure honest realms. Second, after attesta-
to the creation of a CSM region by the P-realm, the            tion, all CSM participation requests are subject to explicit
hypervisor delegates granules for the entire CSM range, if     access-control checks performed by the RMM. Both the P-
they are not already delegated, ensuring that the region is    realm and the C-realm must independently reference each
fully populated and accessible to the P-realm. Conversely,     other using their attested identifiers when issuing CSM-
if the request corresponds to attaching to an existing CSM     related RSI commands. This bidirectional referring rule
region by a C-realm, the hypervisor undelegates any pre-       ensures that, although a malicious realm may arbitrarily
viously delegated granules that fall within the CSM range      invoke CSM-related RSI commands, it cannot establish
of that realm’s protected address space. This mechanism        a CSM with a realm to gain access to a portion of its
guarantees that the CSM region is instantiated exactly         address space, unless the peer realm explicitly agrees.
once in physical memory, maintaining consistency across            Finally, the RMM performs required cache and TLB
participating realms and preventing redundant allocation.      maintenance whenever mappings change. These opera-
     For CSM creation, the hypervisor performs the fol-        tions flush stale translations, ensuring that no realm can
lowing steps for each granule in the CSM range. It first       retain access to the CSM after its permissions have been
issues RMI_RTT_READ_ENTRY to check whether the                 revoked.
target IPA is already populated. If it is not populated,
the hypervisor issues RMI_GRANULE_DELEGATE fol-                Non-CSM Protection. CAEC guarantees that neither the
lowed by RMI_DATA_CREATE_UNKNOWN to delegate a                 P-realm nor the C-realm can access each other’s protected
physical granule and create the corresponding mapping          memory outside the agreed-upon CSM region. During
in the realm’s RTT, respectively. For CSM attachment,          the CSM sharing phase, the RMM validates that sharing
the hypervisor again invokes RMI_RTT_READ_ENTRY.               occurs only at granule-aligned boundaries and for the
If the IPA is already populated, it reclaims the gran-         exact size confirmed by both realms, thereby preventing
ule using RMI_DATA_DESTROY and RMI_GRANULE                     malicious access outside the CSM.
_UNDELEGATE. The hypervisor also ensures that the
RTTs of both the P-realm and the C-realm exist for             Ownership Protection. When a C-realm issues
the CSM range. If necessary, it creates them by is-            RSI_CSM_RESERVE, the RMM explicitly verifies
suing RMI_GRANULE_DELEGATE followed by RMI                     that the requested region does not overlap with any
_RTT_CREATE. As outlined in the adversary model (Sec-          existing mappings. This restriction prevents a C-realm
tion 3.2), we assume that the hypervisor correctly allocates   from delegating access to a CSM region to another
all required resources to ensure uninterrupted realm exe-      realm without the P-realm’s consent. By ensuring
cution. However, failure to allocate these granules does       that all sharing relationships originate from the P-realm,
not compromise the security guarantees of CAEC.                ownership and access remain fully traceable. Such control
                                                               is crucial for allowing the P-realm to reason about which
                                                               realms have visibility into the shared memory and for
5. Security Analysis                                           guaranteeing that, once access is revoked, no realm can
    In this section we provide an in-depth analysis of         retain or reacquire access to the CSM.
different attacks vectors introduced in threat model (Sec-     Host Protection. The RMM in CAEC imposes no con-
tion 3.2), explaining how CAEC remains protected against       straints on how the hypervisor manages CPU scheduling
these threats.                                                 or memory allocation for either CSM or non-CSM regions.
CSM Protection. As discussed in Section 2.1, the               As a result, realms cannot exploit CAEC’s services to
hardware-enforced GPC mechanism ensures that any ac-           obtain more memory or vCPU resources than those ex-
cess to realm-world memory from either the normal world        plicitly provisioned by the hypervisor. This design protects
TABLE 3: Line of code added to components in CAEC                is instruction-accurate, meaning that it correctly executes
      TCB Component               Lines of Code (Extension)      architecturally valid code, but it does not model cycle-
      RMM (v0.5.0) [34]                   1062 (4%)              accurate timing or the performance characteristics of real
      Non-TCB Component                 Lines of Code            processors [41], [45]. Consequently, FVP is well-suited
      kvmtool-cca (v3/cca) [35]              247
      Linux KVM (v5+v7) [36]                 394
                                                                 for evaluating the feasibility and functional correctness of
      CSM Driver                             467                 CAEC on Arm CCA hardware, but it cannot be used for
                                                                 timing or performance measurements.
                                                                 Performance Prototype. At the time of writing, no
the hosting system from DoS attacks originating from             commercial hardware implements the Arm CCA exten-
malicious or misbehaving realms.                                 sions. For performance prototyping, we therefore adopt
                                                                 OPENCCA [46], the first open-source performance proto-
6. Implementation                                                type of Arm CCA. Our performance evaluation can be eas-
                                                                 ily reproduced as OPENCCA runs on cost-effective hard-
    We implement and evaluate CAEC with both func-               ware (i.e., Radxa Rock 5B [47]). OPENCCA constructs
tional and performance prototypes of CCA. Our imple-             the realm world as a separate execution environment
mentation includes both host-side and realm-side exten-          within the normal world. Because current off-the-shelf
sions to support the creation and use of CSM regions.            hardware lacks essential CCA extensions (e.g., GPC), it
Software Stack. We use unmodified Trusted Firmware-              cannot provide hardware-enforced isolated realm world.
A [37] (v2.11) as the Monitor. We adapt the Trusted              Nevertheless, performance prototyping remains feasible
Firmware reference implementation of the RMM [34]                by emulating the realm world in software. This is achieved
(v0.5.0), extending it to support the new and modified           by splitting the normal-world software stack into two ex-
commands introduced by CAEC (Table 2). On the host               ecution domains: one running the standard normal-world
side, we base our hypervisor on linux-cca [36] (v5+v7)           environment, and the other hosting the RMM and realm
and the virtual machine manager on kvmtool-cca [35]              components. A modified Monitor then manages boot and
(v3/cca). We extend the Linux KVM (Kernel-based Virtual          context switching between these domains, effectively em-
Machine) module [38], [39] to support the new RMI                ulating transitions between the normal world and the realm
commands and to delegate physical memory to CSM                  world.
regions in response to the newly defined vCPU exits from             We acknowledge that such a prototype cannot fully
the RMM (Table 2). We modify kvmtool to insert a node            capture the performance characteristics of real CCA hard-
into the guest device tree, reserving a portion of its private   ware. For example, the absence of GPC in the system
address space to be used as the CSM. On the guest side,          registers and memory system, can affect memory access
we add CSM driver to linux-cca [36] (v5+v7). This driver         behavior and caching, introducing discrepancies compared
discovers the reserved region from the device tree, issues       to a genuine CCA environment. While we do not claim
the appropriate RSI commands to create or attach to CSM          that our performance results precisely reflect the cost of
regions, and exposes CSM to user space as a character            CAEC on production-grade CCA hardware, this setup
device. The same driver is used by both P-realms and C-          provides a best-effort approximation until such hardware
realms.                                                          becomes available.
    Table 3 summarizes the code changes introduced by
CAEC, measured in lines of code (LoC). CAEC adds                 7. Evaluation
1,062 LoC to the RMM (29k LoC), resulting in approxi-
mately a 4% increase in its size. The RMM version used
in our prototype (v0.5.0) targets CCA v1.0, which lacks              In this section, we evaluate CAEC by addressing the
planned features such as device assignment and planes            following key questions:
(Section 8.1). These forthcoming features are expected to          •   Q1: Is CAEC fully compatible with CCA hardware?
significantly increase the RMM’s size, making CAEC ’s              •   Q2: What is the performance CAEC through different
relative contribution to the TCB even smaller over time.               tasks?
On the host side, CAEC contributes 247 LoC to kvmtool,              We answer Q1 in Section 7.2 and Q2 in Section 7.3,
of which 213 LoC implement the PCI device used in our            Section 7.4, and Section 7.5.
experimental setup (Section 7.3), and 34 LoC correspond
to core CAEC functionality. CAEC also adds 394 LoC
to the Linux KVM module. On the guest side, the CSM              7.1. Experimental Setting
driver adds 467 LoC.
Functional Prototype. At the time of writing, two                    For functional prototype we set FVP to have two clus-
functional prototypes of Arm CCA are publicly avail-             ters, each with four cores supporting Armv9.2-A and 4GB
able. Arm’s Fixed Virtual Platform (FVP) and Linaro’s            of RAM. All performance experiments are conducted on a
QEMU [40] both provide emulated CCA-compatible hard-             Radxa Rock 5B board [47] equipped with 16GB of RAM
ware. We adopt FVP as our functional prototype be-               and an 8-core processor (4× ARM Cortex-A76 and 4×
cause it is Arm’s official release, fully aligned with the       ARM Cortex-A55). We always create realm VMs with one
CCA specification [11], [41], and widely used in prior           vCPU and pin each vCPU to a specific core, with highest
work [14], [26], [42]–[44]. FVP models key hardware              scheduling priority given to the realm’s vCPU process.
components of an Arm system, including the processors,           For LLM-inference experiments, we use llama.cpp [48]
cache hierarchy, bus traffic, and memory subsystem. It           as our inference engine.
7.2. Compatibility with CCA hardware                          side is achieved through polling over these buffers. Each
                                                              experiment is repeated 1000 times to compute median val-
    To evaluate the compatibility of CAEC with real CCA       ues for latency and CPU usage, while the throughput mea-
hardware, we repeated the data-sharing benchmark (Sec-        surement transfers 1000 messages sequentially. Finally,
tion 7.4) on FVP. We observed no runtime errors or stalls     note that as kvmtool does not natively support sharing
on FVP cores during CSM creation, inference execution,        NW memory pages between two VMs, we extended it by
and CSM termination, demonstrating that CAEC can op-          implementing a new PCI device, with a design similar to
erate on Arm CCA–enabled hardware. In all experiments,        ivshmem [49] in QEMU.
we use the CSM driver to expose the CSM region to user-
space processes.                                              7.4. Data Sharing Benchmark
                                                                   In this section, we evaluate CAEC in the context of
7.3. Communication Benchmark                                  sharing LLMs between realms. We assume a setup where
                                                              multiple realms provide local inference services, each re-
    In this section, we evaluate the effectiveness of CAEC    quiring access to a LLM. We measure the minimum RAM
for communication between realms. We assume two user-         required to run ten typical inference in non-conversational
space programs running in separate realms exchange mes-       mode, without observing a stall or memory-related error.
sages via shared memory. The shared memory is provided        We define the experiment under two configurations: (i) a
either by CAEC or through a shared region in normal           baseline, where each realm maintains its own instance of
world. In each experiment, one side writes messages into      the model, and (ii) model sharing between realms enabled
the shared memory, and the other side reads them. For         by CAEC. We repeat these experiments with two and
the NW shared memory case, we evaluate two config-            three realms, using models of different sizes (all 8-bit
urations: (1) Encrypted communication, in which two           quantized).
sides employ an encryption/decryption protocol (using         Results. Table 4 summarizes the results, showing that
mbedTLS or OpenSSL) to each exchanged message; and            model sharing between realms reduces the overall system
(2) Plaintext communication, in which no encryption is        memory footprint by 16.6% to 28.3%, depending on the
applied. The encryption-based configuration provides con-     model size and number of realms. The reduction becomes
fidentiality and integrity guarantees against an active NW    more pronounced for larger models or when sharing oc-
adversary capable of intercepting or modifying shared-        curs among three realms, demonstrating CAEC’s scala-
memory content. In contrast, when using CAEC, encryp-         bility and efficiency in multi-realm deployments. These
tion is unnecessary because the CSM region is inherently      savings represent a conservative lower bound. In practical
protected from both the NW and other realms.                  deployments, the benefits of CAEC could be significantly
Results. Fig. 5 presents the results for CPU usage, latency   higher because: (1) much larger LLMs may be deployed
(message delivery time), and throughput (data transferred     within realms; and (2) resource sharing can extend beyond
per unit time). Across all metrics, CAEC consistently out-    LLMs to include read-only user-space binaries and shared
performs both encrypted NW-based configurations. Com-         packages. All experiments used the same kernel (43 MB)
pared to OpenSSL, CAEC achieves 24×–212× lower                and filesystem (233 MB).
latency, 25×–209× fewer CPU cycles, and 26×–204×
higher throughput. Against MbedTLS, CAEC delivers             7.5. Runtime Cost Benchmark
4.4×–203× lower latency, 4.5×–200× fewer cycles, and
4.8×–194× higher throughput. In all cases, the perfor-            To evaluate the runtime cost of CAEC, we conducted
mance gap widens as message size increases. These re-         an experiment in which we measure inference latency un-
sults highlight the substantial overhead introduced by        der two configurations. In the baseline setting, the model
cryptographic protection when using NW shared memory          (GPT-2) is stored in the realm’s private memory. In the
for inter-realm communication. Because CAEC provides          second setting, the model is shared with another realm
system-level protection for the CSM, it eliminates the need   and stored in the CSM. We repeat each experiment using
for encryption and its associated per-message costs. Fig. 5   10 representative queries in non-conversational mode.
also reports the performance of plaintext communication       Results. The average inference time is 13.4 seconds in
over NW shared memory. As the results indicate, CAEC          both scenarios, showing that executing a model from CSM
achieves performance equivalent to plaintext NW com-          via the CSM driver achieves native performance and that
munication, demonstrating that the previously observed        the same physical pages can safely be shared between
differences between CAEC and encrypted modes over             two realms without incurring any inference-time over-
NW memory stem entirely from cryptographic processing         head, promising for collaborative or resource-constrained
rather than from differences in memory-access latency,        deployments.
caching effects, or other architectural factors.
    For completeness, we note that in the encryption-         8. Discussion
based modes, each message consists of a small
header—containing session id and seq—followed by the              In this section, we discuss three topics: why CAEC
main payload. The receiver verifies the header for in-        remains compatible with (and orthogonal to) future ex-
tegrity, checks that seq matches the expected value (en-      tensions of Arm CCA (Section 8.1); how CSM can
suring ordering and replay protection). Each side allocates   be enabled in other confidential computing architectures
a buffer on the shared memory to acknowledge the latest       (Section 8.2); and potential future research directions for
sent/received massage. Synchronization between the two        CAEC (Section 8.3).
                                            CAEC                   MBedTLS over NW                      OpenSSL over NW                       Plaintext over NW


                                                                                       103
                  103
Median latency (µs)




                                                                       Throughput (MB/s)
                                                                                                                                        106




                                                                                                                            Median cycles
                                                                                       102
                  102
                                                                                                                                        105
                                                                                       101
                  101
                                                                                                                                        104
                                                                                       100
                      64

                           8
                                6
                                     2
                                          24
                                               48
                                                    96
                                                             92

                                                               4
                                                               8



                                                                                               64

                                                                                                8
                                                                                                6
                                                                                                2
                                                                                               24
                                                                                               48
                                                                                               96
                                                                                               92

                                                                                                 4
                                                                                                 8



                                                                                                                                                64

                                                                                                                                                 8
                                                                                                                                                 6
                                                                                                                                                 2
                                                                                                                                                24
                                                                                                                                                48
                                                                                                                                                96
                                                                                                                                                92

                                                                                                                                                  4
                                                                                                                                                  8
                           12
                                25
                                     51




                                                            38
                                                            76




                                                                                             12
                                                                                             25
                                                                                             51




                                                                                              38
                                                                                              76




                                                                                                                                              12
                                                                                                                                              25
                                                                                                                                              51




                                                                                                                                               38
                                                                                                                                               76
                                          10
                                               20
                                                    40
                                                         81




                                                                                            10
                                                                                            20
                                                                                            40
                                                                                            81




                                                                                                                                             10
                                                                                                                                             20
                                                                                                                                             40
                                                                                                                                             81
                                                              16
                                                         32




                                                                                           16
                                                                                           32




                                                                                                                                            16
                                                                                                                                            32
                                Message size (Bytes)                                          Message size (Bytes)                               Message size (Bytes)
                        (a) Median latency for different                              (b) Communication throughput for
                                                                                                                                  (c) CPU usage per message size.
                                message sizes.                                             different message sizes.
     Figure 5: Communication cost between two realms across four modes: plaintext over NW shared memory, encrypted
     (OpenSSL/MbedTLS) with confidentiality and integrity, and CAEC.

     TABLE 4: Memory footprint comparison of inference services deployed in multiple realms. In the baseline, each realm
     hosts its own LLM; with CAEC, multiple realms share a single model.
                                                                                             2 Realms                                              3 Realms
                        Model             Model Size (MB)            Memory Footprint (MB)                                      Memory Footprint (MB)
                                                                         Baseline / CAEC                 Reduction (%)              Baseline / CAEC               Reduction (%)
                                                                     Total (P-realm, C-realm)                                  Total (P-realm, 2*C-realm)
              GPT-2 [50]                        177               960 (480, 480) / 800 (490, 310)           16.6%          1440 (480, 960) / 1110 (490, 620)         22.9%
           GPT-2 Medium [51]                    437            2000 (1000, 1000) / 1580 (1010, 570)         21.0%        3000 (1000, 2000) / 2150 (1010, 1140)       28.3%



     8.1. Arm CCA Future Extensions                                                                     boundaries and manage sharing, introducing a centralized
                                                                                                        trust dependency that is unsuitable for scenarios involving
         Although CAEC is designed and implemented on top                                               multi-party collaboration.
     of Arm CCA version 1.0, Arm has recently announced its
     planned enhancements for CCA version 1.1 [52]. In this                                             Memory Encryption Context. The Memory Encryp-
     section, we describe why CAEC remains both relevant and                                            tion Context (MEC) extends Arm CCA by introducing
     fully compatible with the upcoming extensions.                                                     hardware-level encryption of memory, providing an addi-
                                                                                                        tional layer of defense-in-depth [52], [54]. Memory pages
     Planes. Plane extension refers to an architectural ex-                                             tagged with the same encryption context are encrypted
     tension that enables the decomposition of a realm into                                             using the same encryption key. As proposed by Arm
     multiple EL0&EL1 execution environments called planes.                                             [52], [54], each realm’s memory can be protected under a
     Planes are managed by a privileged software component                                              single encryption context. Nevertheless, MEC also allows
     known as the paravisor, which runs in plane 0. The paravi-                                         multiple encryption contexts to coexist within a single
     sor is responsible for restricting memory access, emulating                                        realm’s address space [54]. In other words, a realm vCPU
     interrupts, and managing context switching among the                                               can be configured to access multiple encryption contexts
     other planes. Planes were originally proposed to augment                                           simultaneously. Consequently, a new encryption context
     a realm with kernel-level runtime services that cannot be                                          can be assigned to each CSM region, while the memories
     provided by the untrusted hypervisor, such as access to                                            of the P-realm and C-realm(s) remain encrypted under
     a Trusted Platform Module (TPM) [53]. However, since                                               their own respective contexts. Therefore, CAEC is fully
     all planes work in the same realm’s address space, they                                            compatible with MEC hardware extension and MEC’s
     can also be configured to share confidential memory. By                                            trust model, and it can be extended to leverage the MEC’s
     enabling multi-tenant memory sharing within the realm                                              capabilities.
     world, planes can conceptually achieve functionality sim-
     ilar to that of CAEC. Nevertheless, CAEC offers key                                                Device Assignment. This extension enhances CCA archi-
     differences compared to the plane extension, providing                                             tecture to enable secure assignment of physical devices to
     a more flexible and decentralized approach. First, the                                             realms, a concept previously explored in the literature for
     number of inter-CVMs memory sharing CAEC can be                                                    GPUs and other generic devices [42], [44], [55]. Each
     dynamically extended at runtime, whereas the number of                                             realm can independently choose whether to allow an off-
     planes within a realm must be statically defined at boot                                           processor resource, such as an accelerator, to access a
     time. Second, CAEC requires no trusted central entity;                                             region of its address space [52], [56]. Device assignment
     realms can independently decide where and when to share                                            extends RSI and RMI and introduces an additional type of
     memory with each other. In contrast, in the plane exten-                                           metadata granules for realms. We were unable to find any
     sion, all planes must trust plane 0 to enforce isolation                                           interference between the CAEC extension of the RMM
and the device assignment extension to the RMM.               privilege levels in AMD. These isolation mechanisms are
                                                              similar in nature to planes in CCA, but orthogonal to
8.2. Enabling CSM in Other Architectures                      CAEC given that they do not allow sharing across different
                                                              CVMs and follow a strictly hierarchical privilege model
    AMD SEV-SNP [3] and Intel TDX [4] are the two             that can be limiting [60].
major CVM technologies currently deployed by cloud
providers, offering security properties comparable to those   8.3. Future Direction
of realms in Arm CCA. However, the CISC nature of
these architectures makes implementing and evaluating         Formal Verification. Arm CCA’s use of formal methods
CAEC’s functionality significantly more complex-or even       for system design and verification distinguishes it from
infeasible. This section outlines the limitations of these    other confidential computing architectures [61], [62]. Al-
platforms and discusses potential modifications required      though our current work does not provide formal guaran-
to enable CSM-like functionality.                             tees, an important direction for future research is to apply
AMD SEV-SNP. Similar to the GPT in Arm CCA, AMD               formal verification techniques to the CSM design within
SEV-SNP introduces a system-wide data structure called        CCA. Building on recent efforts to formally verify shared-
the Reverse Map Table (RMP), tracking the ownership           memory mechanisms between enclaves [18], extending the
and attributes of physical pages. Unlike the GPT, which       existing formal models of Arm CCA to encompass CSM
only associate pages’ entries with a world state, the         functionality would represent a significant step toward
RMP enforces stricter control by associating pages’ entries   provable security and functional correctness.
with CVM’s identifier, known as Address Space Identifier      Local Attestation. As part of establishing the CSM,
(ASID) [3], [57]. AMD’s hardware checks the RMP en-           realms refer to one another solely through attestation-
tries at the end of each memory access, granting access to    integrated identifiers. In CAEC, each realm owner is re-
a page only if the ASID of the currently executing guest      sponsible not only for remotely attesting its own realm
matches the ASID stored in the corresponding RMP entry.       but also for attesting peer realms with which it intends
As a result, two CVMs cannot simultaneously access the        to associate within the CSM. While remote attestation
same confidential page while the hardware-level ASID          between a realm owner and its own realm is unavoidable,
check is enforced and the RMP only accept one ASID            it is worth exploring whether CAEC could be redesigned
for each page, rendering CSM impossible to implement          to support local attestation between realms. Such a de-
on SEV-SNP without hardware changes.                          sign—especially in scenarios where no secure channel
Intel TDX. To the best of our knowledge, Intel TDX [4]        exists between realm owners and peer realms—could
imposes no inherent hardware limitation that would pre-       significantly improve system performance while still up-
vent the implementation of CSM. However, supporting           holding the security properties expected of attested local
CSM would require modifications to the TDX Module,            interactions.
which has a comparable rule with the RMM in Arm CCA.          CVM Signaling over CSM. CAEC enables direct mem-
TDX maintains a system-wide Physical Address Metadata         ory sharing between CVMs, but the design and integration
Table (PAMT) that tracks the ownership and state of every     of signaling mechanisms over this shared substrate re-
physical page. Whenever a new mapping is established          main underexplored. Developing hypervisor-independent
in a CVM’s address space, the TDX Module checks the           signaling, synchronization, and coordination primitives
PAMT to ensure that the corresponding physical pages          represents a promising direction for robust inter-CVM in-
are not already mapped as protected memory of another         teraction. In particular, integrating CSM-backed signaling
CVM. This restriction could, in principle, be relaxed to      with established abstractions such as virtio could enhance
permit shared mappings between CVMs that mutually             both the portability and extensibility of inter-CVM com-
agree to share memory. The TDX Module also employs            munication. Event-driven synchronization is also feasible
Multi-Key Total Memory Encryption (MKTME) [58] to             through inter-CVM interrupts, which we found can be
encrypt CVM’s memory. MKTME supports memory en-               implemented using standard KVM interfaces—requiring
cryption at page-level granularity, and thus does not im-     no changes to the hypervisor or the RMM—much like the
pose any inherent restriction on maintaining multiple en-     mechanism employed by ivshmem [49]. However, ensur-
crypted regions within a single CVM. For each CVM, the        ing strong security, isolation, and provenance guarantees
TDX Module requests a unique encryption key—identified        for CSM-based signaling remains an open problem and
by a Host Key Identifier (HKID)—and embeds it within          deserves further investigation.
every page table entry of that CVM, ensuring that all pro-
tected memory is encrypted under a single key [4], [59]. A
CSM-aware TDX implementation would therefore require          9. Related Works
an additional encryption key dedicated to each new CSM
region, with its corresponding page table entries tagged      CVM Systems. Cloud providers already offer CVM in-
accordingly to preserve compatibility with the existing       stances for a wide range of applications [7], [9], with
trust model. We acknowledge that above discussions offer      some vendors introducing specialized designs tailored for
a starting point for adapting CSM in TDX, however, a          ML workloads [5], [6]. Recently, new edge-based confi-
comprehensive design and concrete implementation merits       dential computing systems have emerged. For instance,
a separate paper.                                             Samsung’s Islet [63] adopts Arm CCA with a Rust-
    Both AMD’s SEV-SNP and Intel’s TDX implement              based RMM, while Aster [32] introduces sandboxed realm
intra-CVM isolation mechanisms, e.g., the virtual machine     abstractions to secure Android applications. Similarly,
Android’s Virtualization Framework (AVF) [31] enables          multi-CVM systems, where each party can protect its
VMs that are isolated from the Android kernel layer while      proprietary data while efficiently collaborating with, and
providing protected services to Android applications.          providing services to, other parties.
Communication and Memory Sharing. A persistent
challenge in current CVM architectures is the perfor-          Acknowledgment
mance overhead caused by routing I/O and data exchange
through the untrusted hypervisor. It has been shown that           We thank Jon Crowcroft for his invaluable sugges-
hypervisor-mediated services impose significantly higher       tions that helped improve the paper. The research in this
costs in CVMs than in traditional VMs [12]. Directly           paper was supported by the UKRI Open Plus Fellow-
sharing memory between two isolated environments can           ship (EP/W005271/1 Securing the Next Billion Consumer
substantially improve the performance of data exchange.        Devices on the Edge) and an Amazon Research Award
This concept has been explored in previous work for con-       “Auditable Model Privacy using TEEs”.
ventional VMs [64], [65] and enclaves [17]–[19]. Specif-           The authors employed ChatGPT models (GPT-5.1,
ically, Plug-in Enclave [17] enables read-only shared en-      GPT-5, and GPT-4o) as auxiliary tools for editorial sup-
claves for serverless applications, Cerberus [18] focuses      port, exploration of related research, and code debugging.
on the formal verification of memory sharing, and Elas-        All generated material was examined and verified by
ticlave [19] explores sharing models and optimization          the authors. The authors take full responsibility for the
techniques. Sartakov et al. [66] further extend this idea by   accuracy, integrity, and originality of the paper and the
leveraging CHERI capabilities to allow multiple VM-like        released code.
compartments to share a single physical address space.
Arm CCA. As Arm CCA gains adoption, research in                References
this area remains limited but is steadily growing. Li et
al. [24] proposed a formal verification methodology for        [1]   “Intel Software Guard Extensions,” 2025. [Online]. Available:
the RMM. Beyond verification, early systems research                 https://www.intel.com/content/www/us/en/developer/tools/softwa
has explored various extensions to CCA. References [42],             re-guard-extensions/overview.html
[44], [67], [68] represent a number of efforts in this         [2]   A. Limited, “Learn the architecture - TrustZone for AArch64,”
space, introducing new features and capabilities to CCA              2025, accessed Feb 2025. [Online]. Available: https://developer.ar
by modifying its trusted components (the RMM and                     m.com/documentation/102418/latest/
Monitor). SHELTER [67] leverages the GPC mechanism             [3]   “AMD SEV-SNP: Strengthening VM Isolation with Integrity
to support user-space enclaves in the NW. ACAI [44]                  Protection and More.” [Online]. Available: https://www.amd.com/
and CAGE [42] address the integration of accelerators                content/dam/amd/en/documents/epyc-business-docs/white-papers/
                                                                     SEV-SNP-strengthening-vm-isolation-with-integrity-protection-a
into CCA-based systems. Specifically, ACAI enables PCIe              nd-more.pdf
accelerators, while CAGE supports the use of integrated
GPUs within realms. Portal [68] focuses on secure, high-       [4]   “Intel® Trust Domain Extensions (Intel TDX),” 2025. [Online].
                                                                     Available: https://cdrdv2.intel.com/v1/dl/getContent/690419
performance device I/O by enabling direct peripheral ac-
cess from within a realm on mobile SoCs. Other recent          [5]   E. S. GmbH, “The always encrypted ai service,” Mar. 2025,
                                                                     march 7, 2025. [Online]. Available: https://www.privatemode.ai/
work showcases CCA potential for the next-generation of
on device ML. GuaranTEE [26] is a framework for at-            [6]   C. Renzo, L. d’Aliberti, J. Miles, and J. Kovba, “Large language
testable, privacy-preserving machine learning at the edge.           model inference over confidential data using aws nitro enclaves,”
                                                                     2024. [Online]. Available: https://aws.amazon.com/blogs/machi
It combines remote attestation and data protection to sup-           ne-learning/large-language-model-inference-over-confidential-dat
port collaborative ML inference across devices. Abdollahi            a-using-aws-nitro-enclaves/
et al. [14] evaluate the effectiveness of CCA in protecting    [7]   “Confidential space security overview.” [Online]. Available:
ML model during inference, validating its applicability for          https://cloud.google.com/docs/security/confidential-space#: ∼ :
emerging AI workloads.                                               text=,resource%20is%20protected%20by%20an
                                                               [8]   Apple Security Engineering and Architecture (SEAR), User
10. Conclusion                                                       Privacy, Core Operating Systems (Core OS), Services Engineering
                                                                     (ASE), and Machine Learning and AI (AIML), “Private cloud
                                                                     compute: A new frontier for ai privacy in the cloud,” 2024, march
    In this work, we presented CAEC, the first system that           9, 2025. [Online]. Available: https://security.apple.com/blog/privat
enables CSM, a hypervisor-protected (confidential) mem-              e-cloud-compute/
ory which can be shared between multiple CVMs. CAEC            [9]   “Confidential vms on azure,” 2023. [Online]. Available: https:
extends Arm CCA firmware with a principled ownership                 //techcommunity.microsoft.com/blog/windowsosplatform/confiden
model, explicit access-control rules, and attestation exten-         tial-vms-on-azure/3836282
sions that ensure CSM remains inaccessible to the hyper-       [10] A. Limited, “Arm Confidential Compute Architecture,” 2025,
visor and all unauthorized CVMs, while preserving CCA’s             accessed Feb 2025. [Online]. Available: https://www.arm.com/ar
                                                                    chitecture/security-features/arm-confidential-compute-architecture
security guarantees for non-CSM memory. CAEC delivers
substantial benefits for communication and data sharing        [11] T. L. Foundation, “Arm Confidential Compute Architecture
between CVMs. It achieves up to 209× reduction in CPU               open-source enablement,” 2025, accessed Feb 2025. [Online].
                                                                    Available: https://confidentialcomputing.io/webinars/arm-confiden
cycles compared to encryption-based mechanisms over                 tial-compute-architecture-open-source-enablement/
hypervisor-accessible shared memory, and enables sharing
                                                               [12] M. Misono, D. Stavrakakis, N. Santos, and P. Bhatotia, “Confiden-
of large data objects such as LLMs with 16.6%–28.3% re-             tial VMs Explained: An Empirical Analysis of AMD SEV-SNP
duction in overall system memory footprint. CAEC marks              and Intel TDX,” Proceedings of the ACM on Measurement and
a step toward future compartmentalized and collaborative            Analysis of Computing Systems, vol. 8, no. 3, pp. 1–42, 2024.
[13] D. Li, Z. Mi, C. Ji, Y. Tan, B. Zang, H. Guan, and H. Chen,            [32] M. Kuhne, S. Sridhara, A. Bertschi, N. Dutly, S. Capkun, and
     “Bifrost: Analysis and optimization of network {I/O} tax in con-            S. Shinde, “Aster: Fixing the Android TEE ecosystem with Arm
     fidential virtual machines,” in 2023 USENIX Annual Technical                CCA,” arXiv preprint arXiv:2407.16694, 2024.
     Conference (USENIX ATC 23), 2023, pp. 1–15.
                                                                            [33] “RMM Locking Guidelines,” 2025, accessed April 2025. [Online].
[14] S. Abdollahi, M. Maheri, S. Siby, M. Kogias, and H. Haddadi, “An            Available: https://tf-rmm.readthedocs.io/en/latest/design/locking.h
     Early Experience with Confidential Computing Architecture for               tml
     On-Device Model Protection,” arXiv preprint arXiv:2504.08508,
                                                                            [34] TrustedFirmware, “TF-RMM,” 2025, accessed Feb 2025. [Online].
     2025.
                                                                                 Available: https://www.trustedfirmware.org/projects/tf-rmm
[15] H. Lefeuvre, D. Chisnall, M. Kogias, and P. Olivier, “Towards
                                                                            [35] “kvmtool-cca,” 2025, accessed Feb 2025. [Online]. Available:
     (really) safe and fast confidential I/O,” in Proceedings of the 19th
                                                                                 https://gitlab.arm.com/linux-arm/kvmtool-cca/-/tree/cca/v3?ref t
     Workshop on Hot Topics in Operating Systems, 2023, pp. 214–222.
                                                                                 ype=heads
[16] “Advancing security for large language models with nvidia
                                                                            [36] A. Limited, “linux-cca,” 2025, accessed Feb 2025. [Online].
     gpus and edgeless systems,” 2024. [Online]. Available: https:
                                                                                 Available: https://gitlab.arm.com/linux-arm/linux-cca/-/commit/f
     //developer.nvidia.com/blog/advancing-security-for-large-languag
                                                                                 ad35572db
     e-models-with-nvidia-gpus-and-edgeless-systems/
                                                                            [37] “TF-A,” 2025, accessed Feb 2025. [Online]. Available: https:
[17] M. Li, Y. Xia, and H. Chen, “Confidential serverless made efficient
                                                                                 //www.trustedfirmware.org/projects/tf-a
     with plug-in enclaves,” in 2021 ACM/IEEE 48th Annual Interna-
     tional Symposium on Computer Architecture (ISCA). IEEE, 2021,          [38] “Kernel-based Virtual Machine),” 2025. [Online]. Available:
     pp. 306–318.                                                                https://en.wikipedia.org/wiki/Kernel-based Virtual Machine
[18] D. Lee, K. Cheang, A. Thomas, C. Lu, P. Gaddamadugu,                   [39] C. Dall and J. Nieh, “KVM/ARM: the design and implementation
     A. Vahldiek-Oberwagner, M. Vij, D. Song, S. A. Seshia, and                  of the Linux ARM hypervisor,” ACM Sigplan Notices, vol. 49,
     K. Asanovic, “Cerberus: A formal approach to secure and effi-               no. 4, pp. 333–348, 2014.
     cient enclave memory sharing,” in Proceedings of the 2022 ACM
                                                                            [40] Linaro, “qemu,” 2025, accessed Feb 2025. [Online]. Available:
     SIGSAC Conference on Computer and Communications Security,
                                                                                 https://git.codelinaro.org/linaro/dcap/qemu
     2022, pp. 1871–1885.
                                                                            [41] A. Limited, “Fast Models Fixed Virtual Platforms (FVP)
[19] J. Z. Yu, S. Shinde, T. E. Carlson, and P. Saxena, “Elasticlave: An
                                                                                 Reference Guide,” 2025, accessed Feb 2025. [Online]. Available:
     efficient memory model for enclaves,” in 31st USENIX Security
                                                                                 https://developer.arm.com/Tools%20and%20Software/Fixed%20V
     Symposium (USENIX Security 22), 2022, pp. 4111–4128.
                                                                                 irtual%20Platforms
[20] A. Limited, “Realm Management Monitor Specification,” 2025,
                                                                            [42] C. Wang, F. Zhang, Y. Deng, K. Leach, J. Cao, Z. Ning, S. Yan, and
     accessed Feb 2025. [Online]. Available: https://developer.arm.co
                                                                                 Z. He, “CAGE: Complementing Arm CCA with GPU Extensions,”
     m/documentation/den0137/1-0eac5/?lang=en
                                                                                 in Network and Distributed System Security (NDSS) Symposium,
[21] M. Sardar, T. Fossati, and S. Frost, “SoK: Attestation in confiden-         2024.
     tial computing,” ResearchGate pre-print, 2023.
                                                                            [43] Y. Zhang, Y. Hu, Z. Ning, F. Zhang, X. Luo, H. Huang, S. Yan,
[22] Y. Wu, F. Roesner, T. Kohno, N. Zhang, and U. Iqbal, “Isolategpt:           and Z. He, “SHELTER: Extending Arm CCA with Isolation in
     An execution isolation architecture for llm-based agentic systems,”         User Space,” in 32nd USENIX Security Symposium (USENIX Se-
     arXiv preprint arXiv:2403.04960, 2024.                                      curity’23), 2023.
[23] D. Chen, A. Dethise, I. E. Akkus, I. Rimac, K. Satzke, A. Koskela,     [44] S. Sridhara, A. Bertschi, B. Schlüter, M. Kuhne, F. Aliberti, and
     M. Canini, W. Wang, and R. Chen, “Protecting Confidentiality,               S. Shinde, “ACAI: Extending Arm Confidential Computing Archi-
     Privacy and Integrity in Collaborative Learning,” arXiv preprint            tecture Protection from CPUs to Accelerators,” in 33rd USENIX
     arXiv:2412.08534, 2024.                                                     Security Symposium (USENIX Security’24), 2024.
[24] X. Li, X. Li, C. Dall, R. Gu, J. Nieh, Y. Sait, and G. Stockwell,      [45] A. Limited, “Fast Models Reference Guide,” 2025, accessed Feb
     “Design and verification of the Arm confidential compute architec-          2025. [Online]. Available: https://developer.arm.com/Tools%20an
     ture,” in 16th USENIX Symposium on Operating Systems Design                 d%20Software/Fixed%20Virtual%20Platforms
     and Implementation (OSDI 22), 2022, pp. 465–484.
                                                                            [46] A. Bertschi and S. Shinde, “OpenCCA: An Open Framework to
[25] A. Limited, “Arm Confidential Compute Architecture Software                 Enable Arm CCA Research,” arXiv preprint arXiv:2506.05129,
     Architecture Guide,” 2025, accessed Feb 2025. [Online]. Available:          2025.
     https://developer.arm.com/documentation/den0127/0200/?lang=en
                                                                            [47] “ROCK 5B.” [Online]. Available: https://radxa.com/products/roc
[26] S. Siby, S. Abdollahi, M. Maheri, M. Kogias, and H. Haddadi,                k5/5b/
     “GuaranTEE: Towards Attestable and Private ML with CCA,”
                                                                            [48] G. Gerganov, “llama.cpp,” 2023, accessed Feb 2025. [Online].
     in Proceedings of the 4th Workshop on Machine Learning and
                                                                                 Available: https://github.com/ggerganov/llama.cpp
     Systems, 2024, pp. 1–9.
                                                                            [49] Q. Project, “Inter-VM Shared Memory device,” 2023. [Online].
[27] Z. Zhang, C. Gong, Y. Cai, Y. Yuan, B. Liu, D. Li, Y. Guo,
                                                                                 Available: https://www.qemu.org/docs/master/system/devices/ivsh
     and X. Chen, “No Privacy Left Outside: On the (In-) Security of
                                                                                 mem.html
     TEE-Shielded DNN Partition for On-Device ML,” in 2024 IEEE
     Symposium on Security and Privacy (SP). IEEE Computer Society,         [50] OpenAI Community, “openai-community/GPT2,” accessed Feb
     2024, pp. 52–52.                                                            2025. [Online]. Available: https://huggingface.co/openai-communi
                                                                                 ty/gpt2
[28] M. Moon, M. Kim, J. Jung, and D. Song, “ASGARD: Protect-
     ing On-Device Deep Neural Networks with Virtualization-Based           [51] ——, “openai-community/gpt2-medium,” accessed Feb 2025.
     Trusted Execution Environments,” in Proceedings 2025 Network                [Online]. Available: https://huggingface.co/openai-community/gpt
     and Distributed System Security Symposium, 2025.                            2-medium
[29] “Virtual Machine as a core Android Primitive.” [Online]. Available:    [52] “Mad24-410 arm confidential compute architecture open-source
     https://android-developers.googleblog.com/2023/12/virtual-machi             enablement update,” 2024. [Online]. Available: https://resources.li
     nes-as-core-android-primitive.html                                          naro.org/en/resource/rEjhEezEvnNMC3LALzUTrr
[30] A. Limited, “Arm CCA Security Model 1.0,” 2025, accessed Feb           [53] “Evolution of the arm confidential compute architecture by g.
     2025. [Online]. Available: https://developer.arm.com/documentat             stockwell, n. sample & p. howard — oc3.” [Online]. Available:
     ion/DEN0096/latest                                                          https://www.youtube.com/watch?v=1AsvIt7bSLY&t=2086s
[31] “AVF architecture,” 2025, accessed July 2025. [Online]. Available:     [54] A. Limited, “Introducing Arm Confidential Compute Architecture,”
     https://source.android.com/docs/core/virtualization/architecture#m          2025, accessed Feb 2025. [Online]. Available: https://developer.ar
     emory-ownership                                                             m.com/documentation/den0125/0300/Overview
[55] A. Bertschi, S. Sridhara, F. Groschupp, M. Kuhne, B. Schlüter,
     C. Thorens, N. Dutly, S. Capkun, and S. Shinde, “Devlore: Extend-
     ing Arm CCA to Integrated Devices A Journey Beyond Memory
     to Interrupt Isolation,” arXiv preprint arXiv:2408.05835, 2024.
[56] M. Weidmann, “Arm A-Profile Architecture Developments 2022,”
     2022. [Online]. Available: https://community.arm.com/arm-com
     munity-blogs/b/architectures-and-processors-blog/posts/arm-a-pro
     file-architecture-2022l
[57] “SEV Secure Nested Paging Firmware ABI Specification,” 2025.
     [Online]. Available: https://docs.amd.com/v/u/en-US/56860
[58] “Intel® Architecture Memory Encryption Technologies Specifica-
     tion,” 2025. [Online]. Available: https://www.intel.com/content/
     www/us/en/content-details/679154/intel-architecture-memory-enc
     ryption-technologies-specification.html
[59] P.-C. Cheng, W. Ozga, E. Valdez, S. Ahmed, Z. Gu, H. Jamjoom,
     H. Franke, and J. Bottomley, “Intel tdx demystified: A top-down
     approach,” ACM Computing Surveys, vol. 56, no. 9, pp. 1–33, 2024.
[60] C. Castes, A. Ghosn, N. S. Kalani, Y. Qian, M. Kogias, M. Payer,
     and E. Bugnion, “Creating trust by abolishing hierarchies,” in
     Proceedings of the 19th Workshop on Hot Topics in Operating
     Systems, 2023, pp. 231–238.
[61] X. Li, X. Li, C. Dall, R. Gu, J. Nieh, Y. Sait, G. Stockwell,
     M. Knight, and C. Garcia-Tobin, “Enabling realms with the arm
     confidential compute architecture,” 2023.
[62] A. C. Fox, G. Stockwell, S. Xiong, H. Becker, D. P. Mulligan,
     G. Petri, and N. Chong, “A Verification Methodology for the Arm®
     Confidential Computing Architecture: From a Secure Specification
     to Safe Implementations,” Proceedings of the ACM on Program-
     ming Languages, vol. 7, no. OOPSLA1, pp. 376–405, 2023.
[63] “Islet,” 2025, accessed Feb 2025. [Online]. Available: https:
     //github.com/islet-project/islet
[64] S. Sreenivasamurthy and E. Miller, “SIVSHM: Secure inter-vm
     shared memory,” arXiv preprint arXiv:1909.10377, 2019.
[65] Y. Ren, L. Liu, Q. Zhang, Q. Wu, J. Guan, J. Kong, H. Dai, and
     L. Shao, “Shared-memory optimizations for inter-virtual-machine
     communication,” ACM Computing Surveys (CSUR), vol. 48, no. 4,
     pp. 1–42, 2016.
[66] V. A. Sartakov, L. Vilanova, D. Eyers, T. Shinagawa, and P. Piet-
     zuch, “CAP-VMs: Capability-Based Isolation and Sharing in the
     Cloud,” in 16th USENIX Symposium on Operating Systems Design
     and Implementation (OSDI 22), 2022, pp. 597–612.
[67] T. Shen, J. Qi, J. Jiang, X. Wang, S. Wen, X. Chen, S. Zhao,
     S. Wang, L. Chen, X. Luo et al., “SOTER: Guarding Black-box
     Inference for General Neural Networks at the Edge,” in 2022
     USENIX Annual Technical Conference (USENIX ATC 22), 2022,
     pp. 723–738.
[68] F. Sang, J. Lee, X. Zhang, and T. Kim, “PORTAL: Fast and
     Secure Device Access with Arm CCA for Modern Arm Mobile
     System-on-Chips (SoCs),” in 2025 IEEE Symposium on Security
     and Privacy (SP). IEEE, 2025, pp. 4099–4116.
