                                        PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                                   1




                                            An Experimental Evaluation of TEE technology
                                                Evolution: Benchmarking Transparent
                                             Approaches based on SGX, SEV, and TDX
                                                    Luigi Coppolino, Salvatore D’Antonio, Davide Iasio, Giovanni Mazzeo, and Luigi Romano

                                             Abstract—Protection of data-in-use is a key priority, for which Trusted Execution Environment (TEE) technology has unarguably
                                             emerged as a – possibly the most – promising solution. Multiple server-side TEE offerings have been released over the years,
                                             exhibiting substantial differences with respect to several aspects. The first comer was Intel SGX, which featured Process-based TEE
arXiv:2408.00443v1 [cs.CR] 1 Aug 2024




                                             protection, an efficient yet difficult to use approach. Some SGX limitations were (partially) overcome by runtimes, notably: Gramine,
                                             Scone, and Occlum. A major paradigm shift was later brought by AMD SEV, with VM-based TEE protection, which enabled
                                             ”lift-and-shift” deployment of legacy applications. This new paradigm has been implemented by Intel only recently, in TDX. While the
                                             threat model of the aforementioned TEE solutions has been widely discussed, a thorough performance comparison is still lacking in the
                                             literature. This paper provides a comparative evaluation of TDX, SEV, Gramine-SGX, and Occlum-SGX. We study computational
                                             overhead and resource usage, under different operational scenarios and using a diverse suite of legacy applications. By doing so, we
                                             provide a reliable performance assessment under realistic conditions. We explicitly emphasize that – at the time of writing – TDX was
                                             not yet available to the public. Thus, the evaluation of TDX is a unique feature of this study.

                                             Index Terms—Trusted Execution Environment, Confidential Computing, AMD SEV, Intel TDX, Intel SGX, Gramine, Occlum

                                                                                                                   ✦



                                        1    I NTRODUCTION                                                             It is called Trust Domain eXtension (TDX) [7], and builds on
                                                                                                                       lessons learned from SGX.
                                        T    R usted   Execution Environments (TEEs) have
                                             attracted increasing attention in the quest for
                                        secure computing, largely because this technology has
                                                                                                                       While the threat models of these technologies (see Figure
                                                                                                                       1) are well known, and detailed analyses of the tradeoffs
                                        much better performance than alternative solutions,                            of alternative solutions have been made [8][9][10], the
                                        such as Homomorphic Encryption or Secure Multi-Party                           scientific/technical literature provides limited coverage
                                        Computation [1]. Protection of data-in-use in untrusted                        of performance evaluation of TEE offerings, since the
                                        cloud computing platforms was initially enabled by                             currently available comparison of existing TEE approaches
                                        Process-based TEE solutions, which relied on Intel Software                    for transparent — or quasi-transparent — protection of
                                        Guard eXtensions (SGX) [2]. Working with SGX, researchers                      data-in-use from a quantitative point of view is largely
                                        and practitioners from the academia and the industry                           incomplete. This undermines the possibility for security
                                        identified drawbacks which limited the applicability of                        engineers/researchers to take informed decisions about
                                        this technology. Major concerns were related to memory                         the specific TEE solution to use, based on individual
                                        constraints and programming restrictions, which made the                       application requirements. There are some previous research
                                        adaption of legacy software to SGX not only challenging                        works featuring comparative analyses of TEE solutions
                                        but also prone to errors. The enrichment of the Intel                          [11][12][13], which mainly focused on setting side by side
                                        SGX technology with a runtime layer — e.g., Gramine                            SGX and SEV. In just one case, Gramine-SGX was also
                                        [3] (formerly known as Graphene), Occlum [4], or Scone                         included in the evaluation. No experimental evaluation
                                        [5] — helped to mitigate porting issues but at the cost                        exists to date on TDX, since this technology has only
                                        of a larger Trusted Computing Base (TCB). AMD with                             recently been released and — at the time of this writing —
                                        the Secure Encrypted Virtualization (SEV) [6] technology                       there are still no commercial servers available on the market
                                        introduced the concept of a VM-based TEE (also known as                        equipped with TDX technology (and additionally the Linux
                                        Confidential VMs), which is significantly more user-friendly,                  kernel still lacks stable TDX support).
                                        since it allows existing applications to run in the secure                          In this work, we delve into a comprehensive
                                        environment without any modification. The downside, as                         comparative analysis of a wide spectrum of solutions for
                                        compared to Process-based TEE, is a weaker threat model.                       transparent TEE support, ranging from earlier proposals
                                        A VM-based TEE has been recently presented by Intel, too.                      (namely: Gramine-SGX and Occlum-SGX) to the most recent
                                                                                                                       one (namely: TDX). Notably, we are the first ones to
                                        L. Coppolino, S. D’Antonio, G. Mazzeo, and L. Romano are with University       provide an experimental evaluation of TDX (as already
                                        of Naples ’Parthenope’.                                                        mentioned, TDX is not publicly available yet, but we
                                        email: first.last@uniparthenope.it                                             were granted complimentary access to a research instance
                                        D. Iasio is with Trust Up srl.
                                        email: davide.iasio@trustup.it                                                 of an Intel TDX powered machine, which gave us the
                                        Manuscript received January 16, 2024                                           possibility of running our experiments). We investigate
PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                                                     2

the performance tradeoffs of alternative TEE solutions,                   Trustworthy Boundary
with respect to the deployment of legacy applications.                                                                                          Without TEE

Importantly, the study meticulously evaluates performance                Cloud     BIOS and      Host OS and                                    Confidential
                                                                                                               Guest OS   Workloads
                                                                        Admins     Firmware       Hypervisor                                       Data
metrics – such as computational overhead and CPU
utilization – which are crucial in understanding the
                                                                                                                                            VM-based TEE
practical implications of deploying applications on TEE
solutions in real-world scenarios (including the costs of                Cloud     BIOS and      Host OS and
                                                                                                               Guest OS   Workloads
                                                                                                                                                Confidential
                                                                        Admins     Firmware       Hypervisor                                       Data
the cloud platform setup). We selected a diverse set
of legacy applications, which collectively make for a
                                                                                                                                Process-based TEE
substantial benchmark suite, representing typical use cases.




                                                                                                                                      Enclave
                                                                         Cloud     BIOS and      Host OS and                                    Confidential
By doing so, we are able to provide a realistic and                     Admins     Firmware       Hypervisor
                                                                                                               Guest OS   Workloads
                                                                                                                                                   Data
comprehensive assessment of each TEE approach. More
precisely, the experimental activity focuses on workloads
with different resource usage profiles: i) CPU-intensive -              Fig. 1: Trust boundaries of current TEE offerings
TensorFlow and Pytorch; ii) Memory-intensive - Redis and
Hashicorp Vault; iii) I/O-intensive - NGINX and NodeJS. By
thoroughly evaluating the complexity of integration issues       2     BACKGROUND AND M OTIVATION
and the performance trade-offs of alternative TEE solutions      In the domain of confidential computing, there is a
– covering both process-based and VM-based proposals             clear-cut division between Process- and VM- based Trusted
– our study provides practitioners with a compass for            Execution Environment (TEE) (Figure 2), whose common
navigating in the challenging space of effectively using these   goal is ensuring security of data-in-use. In this section, we
technologies for security improvement of legacy software.        overview the technologies that are under the magnifying
The experimental campaign produced the following                 glass of this experimental work. Moreover, we present key
outcomes:                                                        aspects that motivate our paper.

   •   VM-based TEEs are faster (i.e. they have smaller
       execution times), particularly when handling              2.1   Process-based TEE
       memory- and I/O- intensive workloads, as                  In Process-based TEEs, a process is split into two parts:
       compared to Process-based TEEs. They are also             one considered secure (trusted) and the other considered
       characterized by a lower overhead in terms of             not secure (untrusted). The secure part is located in
       resource usage.                                           encrypted memory, managing sensitive computations, while
   •   Although less performing than VM-based TEEs, the          the non-secure part communicates with the operating
       overhead of Process-based TEEs is lower in the case       system and moves I/O from the encrypted memory to
       of CPU-intensive workloads (as opposed to memory-         other parts of the system. Data transfer into and out of
       and I/O- intensive ones). Since the trust model of        this secure memory zone is tightly regulated, with stringent
       Process-based TEEs is stronger, Process-based TEE         controls over the data size and type that is allowed to
       solutions can thus be the right choice for these          cross the boundaries. Ideally, data transferred to or from
       workloads, because in many setups they represent a        the encrypted memory should be encrypted during transit
       good compromise between performance penalty and           and only decrypted within the TEE, ensuring that it is only
       security improvement.                                     accessible to the software operating within the TEE. The
   •   In the domain of VM-based TEEs, TDX outperforms           widely adopted Process-based TEE for server-side security
       SEV in terms of efficiency. We explicitly note that the   is Intel Software Guard eXtension (SGX) [2].
       performance gap between the two security solutions        SGX enables the creation of secure enclaves within the
       is much larger than performance gap between the           processor, isolating sensitive code and data from the rest
       respective CPUs.                                          of the system thanks to the extension of Intel’s Instruction
   •   In the domain of process-based TEEs, Gramine-SGX          Set Architecture (ISA) by 18 new instructions. Sensitive
       consistently outshines Occlum-SGX, not only in            code and data are stored in the Enclave Page Cache (EPC),
       performance but also in terms of resource                 a specific 128 MiB / 256 MiB (for SGX v1 or v2) section
       consumption.                                              of memory set aside during the system startup for storing
                                                                 the code and data of enclaves. Any attempt to access an
The remainder of this work is organized as follows. Section      enclave’s page outside of the EPC results in a page fault. The
2 gives a background on the TEE solutions and defines the        SGX driver collaborates with the CPU to determine which
motivation behind our paper. Section 3 presents previous         pages to remove from the cache. The memory encryption
works focused on the evaluation of the TEE approaches that       engine (MEE) ensures that communication between the
we cover in this paper. Section 4 describes the evaluation       CPU and system memory remains secure, and it is also
methodology and defines the setup used to conduct the            responsible for preventing tampering and providing replay
experiments. Section 5 discusses the outcomes of the             protection. An enclave can only run in user mode (ring3)
experimental campaign. Section 6 reports an analysis of the      since the host OS is considered untrusted. This means that
impact of TEE solutions on Cloud service costs. Finally,         system calls cannot be invoked from inside the TEE. The
Section 7 provides a summary of and comments the main            only way to execute them is through well-defined interface
findings.                                                        calls outside the enclave. An important SGX feature for
PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                                   3

verifying the integrity and security of an enclave is the                  Process-based TEE                        VM-based TEE
                                                                                                                         Trusted
attestation mechanism. SGX supports a local attestation,                Untrusted       Enclave    Trusted               Call trusted
used for communication between enclaves on the same                       Create
                                                                                       Interface                          function
                                                                          Enclave
platform, and a remote attestation used for demonstrating
trustworthiness to external entities.                                   Call trusted               Workload
                                                                                                                         Workload
    Developing applications for SGX can be challenging                   function                  execution
                                                                                                                         execution

because the application must be refactored into trusted
(within the enclave) and untrusted components. This                                                Enclave
porting requires careful design to ensure security and can                                                     Guest Operating System (VM)
be a complex and time-consuming process. This is where                          Operating System                    Operating System

SGX runtimes came to the rescue. They act as intermediate
layers that abstract away the complexity of SGX and allow                           Fig. 2: Process-based vs VM-based TEE
developers to run applications within SGX enclaves with
much fewer changes. By using these runtime environments,
                                                                  range of developers, which helps in its development
developers can more easily take advantage of the security
                                                                  and maintenance. This community involvement can be
benefits of SGX, allowing sensitive or critical applications to
                                                                  important for ensuring the tool stays updated and relevant.
be deployed in potentially untrusted environments.
                                                                  This system introduces Software Fault Isolation-Isolated
The common approach adopted by these runtimes to enable
                                                                  Processes (SIPs) within a LibOS in an enclave’s single
quasi-transparent porting is to execute system calls directly
                                                                  address space. Software Fault Isolation (SFI) is a technique
inside the enclave via a Library OS (LibOS), i.e., a new
                                                                  for sandboxing untrusted modules in different domains.
paradigm trend where kernel functions are available to user
                                                                  The novel aspect of this proposal is the Memory Protection
space (ring3) programs in a form of a library. There are
                                                                  Extensions-based (MPX), Multi-Domain SFI (MMDSFI), which
several runtime environments for Intel SGX (e.g. SCONE,
                                                                  supports an unlimited number of domains without
Gramine, Occlum, SGX-LKL). In this work, we focus on
                                                                  restrictions on their addresses and sizes. This allows
Gramine and Occlum because they stand out among the
                                                                  for enhanced intra-enclave isolation, including isolation
open-source solutions as the widely adopted ones [14].
                                                                  between processes and between a process and the LibOS.
2.1.1 Gramine-SGX                                                 To ensure the security and compliance of these isolation
                                                                  mechanisms, an independent binary verifier called the
Gramine [3] is a runtime coming with a lightweight library
                                                                  Occlum verifier is introduced. This verifier statically checks
OS, which facilitates the use of dynamically loaded libraries
                                                                  ELF binaries to ensure they adhere to MMDSFI’s security
and runtime linking. It stands out as one of the runtimes
                                                                  policies.
that fully accommodate fork/clone/execv system calls,
which are essential for multi-process abstraction, thereby
supporting a wide spectrum of applications. A distinctive         2.2    VM-based TEE
attribute of Gramine [3] is its ability to secure dynamic         VM-based TEEs foresee that an entire VM memory is
loading, allowing users to incorporate any library into an        encrypted using keys sealed in the hardware, which prevent
enclave while ensuring the integrity of the libraries. It         interference by a malicious VMM. Current technologies
enables the safe execution of any binaries, such as those         such as Intel TDX and AMD SEV provide dedicated
using glibc with dynamically linked libraries within the          ephemeral encryption keys for each VM, thus also
enclave. To do this, a user of Gramine must create a              protecting the VMs from each other.
manifest detailing all the trusted libraries and data files
employed within an enclave and then sign this manifest to         2.2.1 AMD SEV
safeguard its integrity before executing the chosen binary        AMD SEV (Secure Encrypted Virtualization) [6] is a security
on SGX. Gramine provides a basic set of system calls in           feature in AMD EPYC processors, which utilizes AMD
its capacity as a LibOS, which can be processed rapidly           Secure Memory Encryption (SME) and AMD Virtualization
due to the low interaction with the host OS. Alternatively,       (AMD-V) for cryptographically separating VMs from the
system calls that are not supported by the library OS are         hypervisor. Each VM gets a distinct, temporary AES key for
meticulously handed over to the host OS. This handover            encrypting memory during operation. The AES mechanism
necessitates exits from and re-entries into the enclave,          in the processor’s memory controller handles encryption
leading to substantial performance costs. Moreover, because       and decryption of data to and from the main memory.
the host OS is considered untrustworthy in the SGX security       These keys for each VM are overseen by the AMD Platform
framework, Gramine also verifies the host OS’s responses.         Security Processor (PSP). A specific bit (C-bit) in physical
Hence, system calls that are passed to the host OS incur          addresses is used to encrypt memory pages. SEV also
greater costs compared to those that the library OS can           offers remote attestation, enabling VM owners to check the
emulate.                                                          integrity of VMs and the SEV platforms. The PSP creates
                                                                  an attestation report, signed by an AMD-certified key,
2.1.2 Occlum-SGX                                                  which VM owners can authenticate along with platform and
Occlum [4], while sharing similarities with Gramine as            guest measurements. AMD has introduced three versions of
a runtime environment, owes its spread and adoption               SEV: the first only secures VM memory confidentiality; the
to its strong community support. Being an open-source             second, SEV-ES (Encrypted State), additionally safeguards
project, Occlum benefits from contributions from a                CPU register states during transitions with the hypervisor;
PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                    4

the third, SEV-SNP (Secure Nested Paging), further protects          of the most popular approaches. Each approach has
against memory attacks like corruption, replaying, and               unique characteristics in terms of design, operation,
remapping.                                                           and performance implications. A comparative analysis
                                                                     is essential to understand the trade-offs and benefits of
2.2.2 Intel TDX                                                      each method. Different applications may have varying
Intel Trust Domain Extensions (TDX) [7], as part of the 4th          requirements. For instance, a blockchain application might
Generation Intel Xeon Scalable Processor, is built using a           prioritize integrity and isolation, a fin-tech application
combination of Intel Virtual Machine Extensions (VMX) ISA            might focus on performance, and a critical infrastructure
extensions, multi-key, total memory-encryption (MKTME)               application might wonder about reliability. A comparative
technology, and a CPU-attested, software module. In                  research can help stakeholders select the most appropriate
addition to these technologies, TDX leverages the Intel              TEE approach for their specific use case.
SGX for what concerns the attestation of Trusted Domains             The balance between security and usability is an age-old
(TDs). Intel TDX enhances the security of TDs by                     challenge. Transparent security aims to minimize user
offering protection against certain types of attacks that            friction while maximizing protection. Our research work
involve physical access to platform memory. This includes            can contribute to designing TEEs that better align with
protection against offline attacks, like DRAM analysis,              user expectations and application requirements. Last but
which encompasses cold-boot attacks, as well as active               not least, with regulations like GDPR and CCPA imposing
attacks on DRAM interfaces. These active attacks might               stringent data protection requirements, understanding the
involve intercepting, altering, moving, splicing, or creating        performance implications of TEEs can assist organizations
aliases for memory contents. However, Intel TDX does not             in making informed decisions that comply with legal
provide a defense against the replay of memory content               standards.
through physical attacks. Confidentiality and Integrity of
Memory and CPU state is achieved by excluding elements
such as firmware, software, devices, and cloud platform              3   R ELATED W ORK
operators from the trusted computing base (TCB), giving              In this section, we report previous research works that
workloads more secure access to CPU instructions and                 experimentally evaluated TEE technologies using different
other technologies. This capability is independent of the            categories of workloads.
cloud infrastructure used to deploy the workload. Remote             Akram et al. [12] analyzed the overhead and memory
attestation is another feature provided by TDX, enabling             layout issues of Intel SGX and AMD SEV. They chose
the validation of a workload’s environment and the security          conventional scientific computing workloads in conjunction
integrity of the TCB.                                                with advanced applications that meet the criteria of the
                                                                     High-Performance Computing (HPC) application space.
2.3       Motivation                                                 Their assessment included workloads traditionally utilized
As the commercial offering of TEE has expanded over the              to benchmark HPC frameworks, particularly the NAS
years, it has become challenging for security engineers and          Parallel Benchmark (NPB) suite. This suite, comprising
decision-makers to select the right solution matching their          different kernels and pseudo-applications, has been a
requirements. Understanding the performance implications             long-standing tool for examining HPC frameworks. In
of TEEs is essential. This necessity stems from the                  addition to traditional scientific computing, they also
need to balance security features with system efficiency,            put attention on machine learning, graph analytics, and
ensuring that the implementation of TEEs does not                    emerging scientific computing workloads. For all the
hinder system performance. Performance metrics such as               evaluations, they conducted tests without hyperthreading
computational overhead, resource utilization, and impact             by restricting the number of threads to the number of
on response times are critical in determining the viability          cores on each platform. Regarding SGX, programs were
and appropriateness of TEEs in various operational                   compiled statically and connected against a modified
contexts. Comprehensive knowledge of these aspects                   standard C library in SCONE. With SEV, instead, they
enables informed decisions about deploying, configuring,             utilized AMD-provided scripts to set up the SEV-enabled
and optimizing TEEs, thus ensuring robust security without           host machine and the guest virtual machine managed by
compromising on performance. Furthermore, the higher                 QEMU.
resource usage given by TEEs also entail higher expenses                 Gottel et al. [11] provided useful insights into the
for cloud deployments. Overall, the decision is taken by             energy, latency, throughput, and processing time of AMD
considering the following questions:                                 SEV and Intel SGX. In their study, authors analyzed
                                                                     these two technologies within the context of large-scale
      •    How does it impact the performance of the application?    distributed systems operating on sensitive data within
      •    How does it impact the isolation of sensitive data?       public cloud infrastructures. The porting of the workload
      •    How does it impact infrastructural costs?                 in SGX was realized using Gramine-SGX. The authors
      •    How does it impact the personnel costs?                   explained the differences and similarities, and threat
      •    How does it impact the migration effort?                  models, of the SGX and SEV hardware architectures.
      •    How does it impact the availability of the application?   They discussed also the engineering efforts in adopting
      •    How does it impact the customer security perception?      both Intel and AMD hardware solutions (individually).
Given the diversity of solutions, we believe it is                   The performance evaluation was conducted on SGX
important to provide an insight into the performance                 and SEV using memory-intensive micro-benchmarks.
PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                                                                     5

Specifically, they executed an evaluation study leveraging          Availability zone
a complete prototype of an event-based publish/subscribe                                                                                                WORKLOAD
                                                                                                  TARGET VM 1
system. Finally, they deployed a realistic scenario and                                           Intel Xeon Platinum
                                                                                                  8480CTDX processor
                                                                                                                                               Redis
                                                                                                                                                            Memory-Intensive
workloads over a publish/subscribe implementation to                                                                                           Vault

gather experimental data in real-world settings. Moreover,                                                              CPU-intensive
                                                                                                                         benchmark
                                                                                                                                               NodeJS
                                                                                                                         algorithms                          I/O-Intensive
the authors recorded the power consumption of the                                                   CPU-intensive
                                                                                                     benchmark          WORKLOAD               NGINX
                                                                                                     algorithms




                                                                                                                          GRAMINE



                                                                                                                                      OCCLUM
publish/subscribe system to identify how it varies based                                             WORKLOAD
                                                                                                                                               PyTorch
                                                                                                                                                            CPU-Intensive
on the adopted technology.                                              BENCHMARK VM
                                                                                                       TDX
                                                                                                                                               TensorFlow
                                                                                                                                SGX
    Mofrad et al. [13] also compared Intel SGX and                    I/O- & Memory- intensive
                                                                         benchmark clients
                                                                                                                                                 CPU-intensive benchmark
AMD SEV, emphasizing their functionality, use cases,                           WRK
                                                                                                                                                        algorithms
security attributes, and performance consequences. The                   Redis-benchmark
                                                                                                       TARGET VM 2                             StarGAN
                                                                                                       AMD’s third-Generation
authors provided information about the characteristics                   Vault-benchmark
                                                                                                       EPYCTM 7763v processor                  ResNet
                                                                                                                                                              Pytorch
and application scenarios of these technologies. They                                                                                          BERT
                                                                                                                                               PyHPC
investigated the design architecture and attack surface of                                                    CPU-intensive
                                                                                                           benchmark algorithms
                                                                                                                                               YAMNet
Intel SGX and AMD Memory Encryption technologies.                                                               WORKLOAD
                                                                                                                                               MoViNet      TensorFlow
                                                                                                                    SEV
To accomplish their benchmarks, they crafted various                                                                                           MoveNet
applications compatible with both SGX and AMD
benchmarks, employing standard C/C++ library functions
                                                                                                 Fig. 3: Experimental Setup
for a uniform code base and an equitable benchmarking
environment. Their focus lies in assessing the performance
of the Intel and AMD Memory Encryption Engine and other
architectural components when operated under similar code
base conditions. Their benchmarks are segmented into three
distinct categories: the first evaluates the TEE’s capacity       same Availability Zone as the workload VM.
for executing intensive floating-point operations without         At the time of writing this paper, there is no public
data wrangling; the second assesses the Memory Encryption         availability of an Intel TDX machine. Experiments on
Engine’s performance of both TEEs through data sorting;           this technology were conducted using a server offered
and the third inspects the overall performance of TEEs            by Intel for research purposes, which mounts an Intel
within a security protocol in a complex application used          Xeon Platinum 8480CTDX (2.0GHz , Turbo at 3.8GHz ).
in public cloud environments.                                     Well-known virtualization tools like QEMU and libvirt are
    Our paper stands out from previous works especially           needed for Intel TDX to enhance the confidentiality of active
for the evaluation of the new Intel TDX technology.               workloads. For the effective operation of a confidential VM,
It introduces a novel perspective in the context of               various elements within the virtualization stack must be
TEE research, evaluating the entire spectrum of current           compatible with TDX hardware. Intel is actively engaged in
approaches for near-transparent porting of applications           integrating comprehensive TDX software support into the
into TEEs. We conduct a comprehensive comparison of               upstream versions of the Linux kernel, QEMU, and libvirt.
the performance across Intel TDX, AMD SEV, Gramine,               We leveraged the patched versions of Linux kernel, QEMU,
and Occlum. Moreover, our work uses a wide set of                 and libvirt to deploy a guest TDX VM. Even in this case, the
workloads characterized by completely different resource          same amount of cores and memory are configured on the
usage profiles.                                                   mounted QEMU Confidential VM.
                                                                  The TDX machine embeds the SGX extension as well. So, we
                                                                  decided to run SGX (i.e., Gramine and Occlum) and Native
4     M ETHODOLOGY                                                runs – useful to set the baseline for the comparison – in the
In the following, we outline the hardware and software            TDX server. In this way, we can provide a fair comparison
settings utilized for the experiments, which are analyzed in      of Native, TDX, and SGX. At the same time, we also want
the rest of the paper.                                            to provide information on how SGX performance compares
                                                                  between the old and new generations of CPUs. Hence, we
                                                                  instantiated a Standard DCsv3-series VM, which uses the
4.1   Environment                                                 3rd Generation Intel Xeon Scalable (Icelake) 8370C (2.9GHz ,
Figure 3 shows our experimental setup. In order to get            Turbo at 3.5GHz ) with the SGXv2 capabilities (i.e., larger
results as comparable as possible, we configured our              EPC and support for dynamic memory allocation (EDMM)).
machines hosting the workloads with the same amount               Experiments on AMD SEV leveraged a Standard
of virtual CPUs (vCPUs) cores (4 cores), the same                 DCasv5-series VM, which uses AMD’s third-Generation
amount of virtual RAM (vRAM) (16GB), and similar NIC              EPYCTM 7763v processor (2.5GHz , Turbo at 3.5GHz ). We
characteristics.                                                  selected this server because it is one of the best-performing
If the workload requires to be stimulated in a client/server      SEV-enabled AMD machine, which is comparable with the
topology, there is the need for an external benchmark client      Intel machine.
to do requests to the server. In this case, in order to prevent   In terms of software, all VMs were configured with Ubuntu
interference, a separate VM was deployed. Low-latency             22.04.3 LTS. We use the latest versions of Gramine-SGX
channels between the client and server are important to get       (v1.6), and Occlum (v0.30.0). The SGX SDK software stack
fair results. Hence, the benchmark VM was deployed in the         relies on version 2.22.
PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                         6

4.2       Managing CPUs with different Clock Frequencies               •    Redis3 : Known for its efficiency as an in-memory
In our experimental setup, we make an identical                             key-value store, we utilized Redis for operations like
configuration of vCPUs and vRAM across the different                        deep in-memory scanning, and typical SET and GET
nodes. However, there are still some factors that could                     commands, which are memory-intensive.
potentially skew the fairness of our results such as the               •    Hashicorp Vault4 : This tool is used for key and secrets
range of CPU clock frequencies. The clock frequency varies                  management and is known to be memory-intensive,
slightly among the nodes we selected for our experiments.                   making it a suitable test for our memory workload
This variation is significant enough that it must be                        category.
considered when analyzing our experimental results to               I/O-intensive Workloads. To evaluate the performance
ensure accuracy and fairness.                                    under I/O stress, we selected:
To address this potential discrepancy, we adopt a method
of normalization for our calculated overheads. This                    •    NGINX5 : A high-performance web server, NGINX
normalization process involves using microbenchmark                         is used for serving web content, which is typically
results that are publicly available for the specific CPUs used              I/O-intensive due to the nature of web traffic and
in our servers [15][16][17]. These benchmarks provide a                     data transfer.
detailed analysis of the performance capabilities of these             •    NodeJS6 : Known for server-side scripting, NodeJS
CPUs under various conditions. By incorporating these                       applications often involve significant I/O operations,
benchmark results into our analysis, we can adjust our                      especially when handling multiple concurrent
data to account for the differences in clock frequency. This                requests.
normalization allows us to compare performance metrics
                                                                     For each of these workloads, we conducted multiple runs
more accurately across different hardware setups. It ensures
                                                                 to ensure reliability and accuracy in our results. Specifically,
that any observed differences in the experimental results
                                                                 we set a confidence interval of 95% and empirically verified
are due to the factors we are testing, rather than inherent
                                                                 that 10 repetitions of our experiments were enough to
differences in the hardware’s basic processing speed. In
                                                                 achieve the aforementioned target. The outcomes were
essence, this approach helps us isolate the variables we
                                                                 averaged to account for any anomalies and to provide
are interested in studying, by mitigating the impact of
                                                                 a more accurate representation of the performance. This
an external variable – the clock frequency range – that
                                                                 rigorous testing methodology allows us to comprehensively
could otherwise introduce an element of unfairness into
                                                                 assess the effectiveness of TEE approaches across a spectrum
our results. This careful consideration and adjustment for
                                                                 of real-world applications, ensuring that our findings are
hardware differences underscore the rigor and precision we
                                                                 both valuable and applicable to a wide range of scenarios.
are applying in our experimental analysis.

                                                                 4.4       Benchmarks
4.3       Workloads
                                                                 We employed a variety of benchmarking tools to stimulate
To ensure that our evaluation of Trusted Execution
                                                                 the different workloads. It is important to notice that their
Environment (TEE) approaches is thorough and reflective
                                                                 final configuration — e.g., the number of connections, and
of real-world scenarios, it is crucial to test them across a
                                                                 the ranges of parallel clients — was obtained empirically
diverse range of workloads. These workloads should mirror
                                                                 after several preliminary experiments aimed at reaching the
the variety of applications commonly used in practice, each
                                                                 workload saturation point.
with its unique resource utilization characteristics. We have
                                                                     Redis. We used redis-benchmark, a tool specifically
carefully selected several prevalent workloads, categorized
                                                                 designed for the REDIS key-value store. It is used to
based on their primary resource demands: CPU-intensive,
                                                                 measure the performance of a Redis server by running
memory-intensive, and I/O-intensive.
                                                                 a series of predefined tests. In our study, we used
   CPU-Intensive Workloads. For tasks that demand
                                                                 redis-benchmark to make typical operations of SET and
substantial      CPU      resources,     particularly      for
                                                                 GET, thus evaluating the throughput and latency of the
computation-intensive processes, we selected the following
                                                                 Redis server during writing and reading from memory.
workloads:
                                                                 In terms of configuration, we kept the total number of
      •    TensorFlow1 : This is a widely used framework in      connections to a fixed value of 100k and varied the number
           the field of deep learning. We specifically focused   of parallel clients from 10 to 1000.
           on running machine learning inference algorithms,         NGINX & NodeJS. The wrk2 benchmark was adopted
           which are known for their high CPU usage due to       to generate a significant load against NGINX and NodeJS.
           complex calculations.                                 It provides a flexible scripting interface that allows us to
      •    PyTorch2 : Another deep learning framework, PyTorch   simulate different types of HTTP requests, which is crucial
           is renowned for its efficiency in performing          for testing the performance of NGINX as a web server and
           computations that require significant CPU power.      NodeJS in server-side scripting scenarios. By adjusting the
                                                                 number of connections, threads, and the duration of the test,
   Memory-intensive Workloads. For workloads that
predominantly consume memory resources, we included:               3. https://redis.io/
                                                                   4. https://www.hashicorp.com
 1. https://www.tensorflow.org                                     5. https://nginx.org
 2. https://pytorch.org                                            6. https://nodejs.org
PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                    7
                                                                                                  Redis (SET)
we were able to assess how these servers handle high traffic                           1
                                                                                                                Native
and concurrent connections. The benchmark was configured                            0.9
                                                                                                                TDX
with a duration of 30s, a fixed number of connections to 100,                       0.8
                                                                                                                SEV
and a varying number of clients ranging from 10 to 16000.                           0.7
                                                                                                                Gramine
    Vault. The vault-benchmark tool — specifically designed                         0.6
                                                                                                                Occlum




                                                                          Latency
for Hashicorp Vault — helps in evaluating the performance
                                                                                    0.5
of Vault in various scenarios, including reading and
                                                                                    0.4
writing secrets, authentication requests, and other secret
                                                                                    0.3
management operations. We used the vault-benchmark to
determine the throughput and response times of Vault                                0.2

during static secret writes operations, which is critical for                       0.1
understanding its scalability and reliability in a production                          0
environment. The benchmark was tuned with numkvs =                                          0       0.5                   1
                                                                                                Throughput
100, and a kvsize varying in the range [10, 800].
    PyTorch. The benchmarking of PyTorch involved the                Fig. 4: Redis Performance – Throughput vs Latency
adoption of built-in algorithms, which range from image
                                                                                                  Vault
processing and classification to natural language processing
                                                                                        1
and high-performance computing simulations. Specifically:
                                                                                      0.9                       Native
      •    StarGAN (pytorch stargan-cpu) - Image-to-image                             0.8                       TDX
           translations.                                                              0.7                       SEV
      •    ResNet (phlippe resnet-cpu) - Image classification.                                                  Gramine
                                                                                      0.6




                                                                            Latency
      •    BERT (BERT pytorch-cpu) - Natural language                                                           Occlum
                                                                                      0.5
           processing.
                                                                                      0.4
      •    PyHPC (pyhpc isoneutral mixing-cpu) - Scientific
           simulations in fluid dynamics and climate modeling.                        0.3
                                                                                      0.2
   TensorFlow. Even in this case, we used built-in models to
                                                                                      0.1
evaluate performance:
                                                                                       0
      •    YAMNet - a deep learning model designed for audio                                0        0.5                  1

           event detection and classification.                                                  Throughput

      •    MoViNet (movinet stream) - a family of models
                                                                     Fig. 5: Vault Performance – Throughput vs Latency
           optimized for video understanding, particularly for
           streaming video analysis.
      •    MoveNet - a cutting-edge model for human pose
                                                                 throughput, although Gramine performs better than Occlum,
           estimation, known for its speed and accuracy. It is
                                                                 which experiences a sharp peak, and then a rapid decrease,
           designed to be lightweight and efficient, making it
                                                                 suggesting inefficiency, especially at lower throughputs. The
           suitable for real-time applications.
                                                                 TDX solution (red line with square marker) has surprisingly
                                                                 the highest throughput and a latency that is comparable
5     E XPERIMENTAL R ESULTS                                     with the one observed on the Native (black line with circle
In this section, we dive into the analysis of results            marker). The Native solution has a steady increase in latency
obtained during our experimental campaign. The focus             with high throughput. Furthermore, we can notice that
is on interpreting the data collected, evaluating the            Native and TDX have a similar trend. SEV (green line
outcomes against our hypotheses, and understanding               with triangle marker) has higher latency at the beginning,
the implications of these findings. For CPU-Intensive            which sharply increases with a small increase in throughput,
workloads, we compare the execution time among the               indicating a potential bottleneck in handling higher loads.
different technologies. For Memory and I/O-intensive             However, it is important to notice that the difference in
workloads, instead, we analyze the throughput and latency.       performance between TDX and SEV depends on two factors:
In all cases, we also report details of an analysis of the       the CPU typology and the security technology itself. The
average CPU utilization.                                         impact of the CPU typology can be obtained using publicly
All graphs are normalized as follows:                            available benchmarks [15][17], which tell us that the AMD
                                                                 CPU is on average 40.7% slower than the Intel CPU,
               xnorm = (x − xmin )/(xmax − xmin )                which hosted the execution of all the other versions of the
                                                                 workloads (Native, TDX, Gramine, Occlum). If we subtract
                                                                 the 40.7% we can argue that the actual overhead of SEV
5.1       Memory-Intensive Workloads                             with respect to TDX can be considered of ≈ 22%.
Figure 4 shows the graph on Redis performance. The x-axis        In Figure 5, we report the Vault performance. The rightest
refers to the throughput and the y -axis to the latency. As      points correspond to the lowest kvsize. The increase of kvsize
expected, Gramine (yellow line with ’X’ marker) and Occlum       causes the decrease of the throughput and a rise in the
(blue line with star marker) have the worst performance. It      latency. Even in this case, we observed that TDX provides
can be observed they reported the highest latency and low        the highest throughput. It is interesting to notice that SEV
 PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                                                                           8
                          PYTORCH                                                                                                                         NGINX
                        9000                                                                                                                     1
  Inference time (ms)
                        8000                                                                                                                                            Native
                                                                                                                                               0.9
                        7000                                                                                                                                            TDX
                        6000                                                                                                                   0.8                      SEV
                        5000                                                                                                                   0.7                      Gramine
                        4000                                                                                                                                            Occlum
                                                                                                                                               0.6




                                                                                                                                     Latency
                        3000
                        2000                                                                                                                   0.5
                        1000                                                                                                                   0.4
                           0
                                                     train[STARGAN]              eval[STARGAN]            train[BERT]                          0.3
                                                                                                                                               0.2
                                                                             PYTORCH
                      400                                                                                                                       0.1
                        350                                                                                                                      0
Inference time (ms)




                        300                                                                                                                           0      0.5                  1
                        250                                                                                                                                Throughput
                        200
                        150                                                                                                  Fig. 8: NGINX Performance – Throughput vs Latency
                        100                                                                                                                               NodeJS
                         50                                                                                                                       1
                                                                                                                                                                        Native
                         0                                                                                                                      0.9                     TDX
                                      eval[RESNET] train[RESNET]                   eval[BERT]      PYHPCv1      PYHPCv2
                                                                                                                                                0.8                     SEV
                                                         Native      TDX     SEV       Gramine       Occlum                                                             Occlum
                                                                                                                                                0.7
                                                                                                                                                                        Gramine
                                                                                                                                                0.6




                                                                                                                                      Latency
                                    Fig. 6: PyTorch Performance – Inference Time                                                                0.5
                                                                        TENSORFLOW-LITE                                                         0.4
                                                    35
                                                                                                                                                0.3
                                                    30
                                                                                                                                                0.2
                              Inference Time (ms)




                                                    25
                                                                                                                                                0.1
                                                    20
                                                                                                                                                  0
                                                    15                                                                                                0      0.5              1
                                                    10                                                                                                    Throughput
                                                     5
                                                                                                                                Fig. 9: NodeJS Performance – Throughput vs Latency
                                                    0
                                                               yamnet             movinet_stream          movenet
                                                            Native         TDX       SEV        Gramine       Occlum
                                                                                                                          experienced a low inference time, which sometimes is even
                              Fig. 7: TensorFlow Performance – Inference Time                                             better than the Native one. While Gramine-SGX and SEV
                                                                                                                          reported a slightly higher execution time. Occlum was the
                                                                                                                          worst one with a higher inference time, up to 6×.
 has a throughput similar to the Gramine and Native solutions                                                             What becomes evident from these findings is that
 but at the same time, it has the lowest latency. A different                                                             Process-based TEEs tend to experience only minor
 story is Occlum, which experienced very bad performance                                                                  performance degradation when subjected to CPU-intensive
 as can be noticed by the graph highlighting the high latency                                                             workloads. In certain instances, their performance closely
 and the low throughput.                                                                                                  matches that of VM-based TEEs, while in others, such as
                                                                                                                          with Gramine-SGX, they even surpass VM-based TEEs in
 5.2                          CPU-Intensive Workloads                                                                     terms of performance.
 Figures 6 and 7 show bar graphs depicting the inference
 time of PyTorch and TensorFlow workloads, respectively. On                                                               5.3     I/O-Intensive Workloads
 the x-axis, we report the different benchmarks used for the                                                              Figure 8 shows the performance of NGINX. The Native
 evaluation.                                                                                                              has the highest throughput. The latency remains the lowest
 For what concerns PyTorch, as expected the Native                                                                        across all throughputs. TDX shows a significant drop in
 environment consistently exhibits the shortest inference                                                                 throughput compared to Native, stabilizing just above 0.4.
 times across all benchmarks. Gramine-SGX performs                                                                        The latency is low when the throughput is below this point
 exceptionally well, often approaching the performance                                                                    but rises sharply as the throughput increases. The average
 of the Native environment. Unlike the other evaluations,                                                                 overhead of TDX with respect to the Native is 28.6%. SEV
 Gramine-SGX behaves better than TDX across all                                                                           has a lower maximum throughput than TDX. The latency is
 benchmarks. Occlum also exhibits better performance                                                                      in the same range of TDX at low throughputs but does not
 than usual, which is on the same level as TDX. SEV                                                                       increase as sharply. Again, if we remove the impact of the
 demonstrates significantly longer execution times, with                                                                  AMD CPU, we can consider SEV 8.7% slower than TDX.
 approximately 40% of this increase attributed to inherent                                                                Gramine-SGX exhibits a similar pattern to SEV, but with
 CPU characteristic differences.                                                                                          slightly higher latency across all throughput levels. Even in
 In the case of TensorFlow, the situation is different. TDX                                                               this case, Gramine-SGX behaved better than Occlum-SGX but
PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                          9
                                                        CPU Usage
                                             Native       TDX        SEV       Gramine       Occlum
                               450
                               400
                               350


             Average CPU (%)
                               300
                               250
                               200
                               150
                               100
                                50
                                0
                                     Redis     NGINX            NodeJS          Vault        PyTorch      TensorFlow

                                                      Fig. 10: Average CPU Utilization


still slower than the VM-based TEEs, reporting an overhead               6   I MPACT ON C LOUD S ERVICE C OSTS
of 67.6%.
Figure 9 compares the performance of the NodeJS workload.                This section aims to assess how different TEE solutions
The Native has the best performance as before, showing                   influence the costs associated with Cloud instances,
high throughput and low latency. While TDX has a slightly                particularly when striving to achieve predefined
higher latency than SEV. It is important to highlight                    performance targets. To facilitate a precise estimation, we
that, for this particular workload, both Gramine-SGX and                 first collated the hourly rates from Azure Cloud for various
Occlum-SGX were not able to sustain the same amount of                   machine types that meet the TEE hardware requirements.
concurrent benchmark requests used for TDX, SEV, and                     We started from the baseline configuration used during
Native (in the range of [10, 8000]). The webserver stuck                 our experimental campaign, which consisted of virtual
after 500 requests. Hence, a smaller range of requests has               machines equipped with fixed disk size, 4 vCPUs, and
been used (i.e., [10, 500]). This explains why the latency of            16 GB of vRAM. To evaluate how the variation of vCPUs
Gramine-SGX and Occlum-SGX is extremely low compared                     and vRAM affects performance, we conducted experiments
to the other approaches.                                                 that adjusted these parameters. Notably, certain workloads,
                                                                         such as Redis, showed no performance gains from increased
                                                                         core counts due to their single-threaded nature. In such
5.4   Resource Usage                                                     instances, we deploy multiple instances in a clustered
Besides evaluating the speed of our workloads, we are                    configuration under a load balancer to achieve the desired
also interested in examining the CPU utilization across the              throughput. We point out that the increase of CPU cores in
various TEE approaches to better understand the trade-offs               the Cloud VM configuration can only be done in a power
between security and computational efficiency.                           of two. Regarding TDX, in the absence of official pricing
In Figure 10 we show the average CPU usage for the                       at the time of this study, we provided an estimated cost.
different workloads. As expected, the Native runs exhibit                This estimate is based on the announced future availability
the lowest CPU usage for all applications. TDX shows                     of confidential TDX VMs on Azure, extrapolating from the
competitive CPU usage, close to Native levels in most                    current cost structure of similar VM services and accounting
applications. AMD’s SEV consistently shows higher CPU                    for the expected premium that TDX’s enhanced security
usage compared to TDX and sometimes even higher                          features would necessitate. Regarding SGX, we report
than Gramine and Occlum. Both process-based TEEs show                    costs for two typologies of instances having support for
variable CPU usage across different applications. Gramine                SGX v1 and v2 architectures. We selected representative
generally maintains moderate CPU usage, indicating a                     workloads for each category — i.e., Redis, PyTorch, NGINX
balanced performance. Occlum, however, has notably high                  — and varied benchmark performance targets in a range,
CPU usage with PyTorch, which could be indicative of less                which is based on the results obtained during our previous
efficient handling of CPU-intensive workloads or a lack of               evaluations. We highlight that regardless of the CPU cores,
optimization for this particular application. For Redis and              the cost of SGX machines is the highest, followed by the
NodeJS, all TEEs have relatively similar CPU usage, with                 TDX one, and lastly SEV.
TDX marginally outperforming the others. This suggests                   Figure 11 graphically shows the cost per hour of
that for certain types of workloads, the choice of TEE                   TEE-enabled VMs for each particular selected workload.
might not significantly impact CPU efficiency. The PyTorch               Regarding Redis (Figure 11a), it can be noticed that no
workload stands out with its high CPU usage in the Native                increase of CPU cores — thus increase of cost — is needed
environment, while TDX optimizes this usage considerably.                for Standard and TDX VMs. Contrariwise, SGXv1 machines
Occlum, however, seems to struggle with this workload.                   require more cores starting from 10k RPS. While, SGXv2
TDX appears to be the most efficient in terms of CPU usage               and SEV increase costs starting from 50k RPS. For what
across a range of applications, closely followed by Gramine.             concerns PyTorch (Figure 11b), we used as a benchmark the
SEV tends to have higher CPU overhead, while Occlum’s                    training of the BERT algorithm. It can be noticed that SEV
performance is highly variable, performing well in some                  is the one that costs more when the inference time must
cases but not in others.                                                 be lower than 3s, and also it required much more cores
 PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                                                                                                                   10
                                      Redis                                                                              PyTorch
                    1.4                                                                                 2.5
                                                                                                                                                    while being a good compromise for CPU-bound tasks, tend
                    1.2                                                                                                                             to exhibit significantly higher resource usage overall.
                                                                                                         2




                                                                                    Cost ($) per hour
                      1
Cost ($) per hour



                                                                                                                                                    In terms of costs, in general, SGX deployments are the most
                                                                                                        1.5
                    0.8
                                                                                                                                                    expensive, followed by TDX, and then SEV. Using SGX or
                    0.6                                                                                   1                                         SEV with memory-intensive workloads requires more CPU
                    0.4
                                                                                                        0.5                                         cores, which results in higher costs (whereas this is not the
                    0.2
                                                                                                                                                    case with TDX). For CPU-intensive workloads, the number
                     0                                                                                   0
                           1k       5k     10k     50k                      100k                              100      250     500     1k    3k     of cores was increased with respect to a Standard VM for all
                                     Throughput (rps)                                                                  Inference Time (ms)          types of VMs. For I/O-intensive ones, SGX VMs required
                      Standard VM     SGXv1 VM                          SGXv2 VM                         Standard VM      SGXv1 VM       SGXv2 VM
                      SEV VM        (a)TDXRedis
                                           VM                                 NGINX                      SEV VM        (b)TDX
                                                                                                                           PyTorch
                                                                                                                              VM
                                                                                                                                                    a double level of cores due to the significant overhead
                                                             3                                                                                      suffered by the workloads.
                                                            2.5
                                        Cost ($) per hour




                                                             2
                                                                                                                                                    ACKNOWLEDGMENTS
                                                            1.5
                                                                                                                                                    This project has received funding from the European
                                                              1
                                                                                                                                                    Union’s Horizon Europe Research and Innovation
                                                            0.5
                                                                                                                                                    Programme under Grant Agreement No. 101070670
                                                             0                                                                                      (ENCRYPT - A Scalable and Practical Privacy-preserving
                                                                  25k       50k   100k 200k                       300k
                                                                             Throughput (rps)                                                       Framework).
                                                              Standard VM     SGXv1 VM                        SGXv2 VM
                                                                                                                                                    The work made in this paper was also funded by the
                                                              SEV VM          TDX VM
                                                                                                                                                    European Union under NextGenerationEU. PRIN 2022 Prot.
                                                                         (c) NGINX                                                                  n. 202297YF75.
                                     Fig. 11: Costs of Cloud deployments                                                                            The authors would like to thank Alessandro De Crecchio
                                                                                                                                                    for his valuable contribution to the experimental campaign.

 when we targeted lower inference times. SGX VMs had
 a trend similar to the TDX one. This was expected given
                                                                                                                                                    R EFERENCES
 the performance results we obtained for CPU-intensive                                                                                              [1]   L. Coppolino, S. D’Antonio, G. Mazzeo, and L. Romano,
 workloads. Finally, regarding NGINX, the TDX machine                                                                                                     “A comprehensive survey of hardware-assisted security: From
                                                                                                                                                          the edge to the cloud,” Internet of Things, vol. 6, p.
 doubles the cores only when a target of 300k RPS has to be                                                                                               100055, 2019. [Online]. Available: https://www.sciencedirect.
 achieved. While, for the SEV one, it happens with a 200k                                                                                                 com/science/article/pii/S2542660519300101
 RPS target. SGX machines, instead, require a very high                                                                                             [2]   F. McKeen, I. Alexandrovich, I. Anati, D. Caspi, S. Johnson,
                                                                                                                                                          R. Leslie-Hurd, and C. Rozas, “Intel® software guard extensions
 number of cores leading to significantly larger costs. Using                                                                                             (intel® sgx) support for dynamic memory management inside an
 100k RPS, the situation gets better.                                                                                                                     enclave,” in Proceedings of the Hardware and Architectural Support
                                                                                                                                                          for Security and Privacy 2016, ser. HASP ’16. New York, NY, USA:
                                                                                                                                                          Association for Computing Machinery, 2016. [Online]. Available:
 7                        C ONCLUDING R EMARKS                                                                                                            https://doi.org/10.1145/2948618.2954331
                                                                                                                                                    [3]   C.-C. Tsai, D. E. Porter, and M. Vij, “Graphene-sgx: A practical
 This paper features an in-depth comparative analysis –                                                                                                   library os for unmodified applications on sgx,” in Proceedings of the
 covering cost, effort, security, and performance – of some                                                                                               2017 USENIX Conference on Usenix Annual Technical Conference, ser.
 of the major solutions for transparent TEE protection of                                                                                                 USENIX ATC ’17. USA: USENIX Association, 2017, p. 645–658.
 existing applications. We examined the performance and                                                                                             [4]   Y. Shen, H. Tian, Y. Chen, K. Chen, R. Wang, Y. Xu, Y. Xia, and
                                                                                                                                                          S. Yan, “Occlum: Secure and efficient multitasking inside a single
 the cost differences of VM-based TEEs (specifically, Intel                                                                                               enclave of intel sgx,” in Proceedings of the Twenty-Fifth International
 TDX and AMD SEV) against Process-based TEEs (i.e., Intel                                                                                                 Conference on Architectural Support for Programming Languages
 SGX) when used with runtimes such as Gramine-SGX                                                                                                         and Operating Systems, ser. ASPLOS ’20. New York, NY, USA:
                                                                                                                                                          Association for Computing Machinery, 2020, p. 955–970. [Online].
 and Occlum-SGX. The study provides decision-makers                                                                                                       Available: https://doi.org/10.1145/3373376.3378469
 with insights useful for understanding which specific                                                                                              [5]   S. Arnautov, B. Trach, F. Gregor, T. Knauth, A. Martin, C. Priebe,
 TEE solution best suits the requirements/constraints of                                                                                                  J. Lind, D. Muthukumaran, D. O’Keeffe, M. L. Stillwell,
 a given setup. Our research demonstrates that for I/O-                                                                                                   D. Goltzsche, D. Eyers, R. Kapitza, P. Pietzuch, and C. Fetzer,
                                                                                                                                                          “Scone: Secure linux containers with intel sgx,” in Proceedings
 and Memory- intensive workloads the VM-based TEEs are                                                                                                    of the 12th USENIX Conference on Operating Systems Design and
 much better performing than Process-based ones, while for                                                                                                Implementation, ser. OSDI’16. USA: USENIX Association, 2016,
 CPU-intensive workloads, process-based TEEs emerge as                                                                                                    p. 689–703.
                                                                                                                                                    [6]   D. Kaplan, J. Powell, and T. Woller, “AMD Memory
 a good option since the gain in terms of security comes                                                                                                  Encryption,” AMD Developer Central, Advanced Micro
 at a lower cost of performance. Our findings indicate that                                                                                               Devices, Inc., pp. 1–12, Apr 2016, [Online]. Available:
 TDX behaves better than SEV, a discrepancy that cannot                                                                                                   https://developer.amd.com/wordpress/media/2013/12/AMD
 be solely attributed to the intrinsic differences in Intel and                                                                                           Memory Encryption Whitepaper v7-Public.pdf.
                                                                                                                                                    [7]   “Intel TDX,” Intel Developer Reference, Nov 2023, [Online].
 AMD CPUs performance. Even after adjusting for potential                                                                                                 Available:         https://www.intel.com/content/www/us/en/
 CPU-related performance disparities, TDX does better in                                                                                                  developer/tools/trust-domain-extensions/overview.html.
 resource usage efficiency. In the area of process-based TEEs,                                                                                      [8]   R. Sahita, D. Caspi, B. Huntley, V. Scarlata, B. Chaikin,
 Gramine-SGX consistently outperforms Occlum-SGX across                                                                                                   S. Chhabra, A. Aharon, and I. Ouziel, “Security analysis of
                                                                                                                                                          confidential-compute instruction set architecture for virtualized
 all evaluated parameters, including resource consumption.                                                                                                workloads,” in 2021 International Symposium on Secure and Private
 However, our study also notes that process-based TEEs,                                                                                                   Execution Environment Design (SEED), 2021, pp. 121–131.
PAPER UNDER REVIEW AT IEEE TRANSACTIONS ON DEPENDABLE AND SECURE COMPUTING                                                 11

[9]  F. Hetzelt and R. Buhren, “Security analysis of encrypted virtual       Giovanni Mazzeo PhD, is an Assistant
     machines,” in Proceedings of the 13th ACM SIGPLAN/SIGOPS                Professor at the Department of Engineering of
     International Conference on Virtual Execution Environments, ser. VEE    the University of Naples Parthenope, Italy. His
     ’17. New York, NY, USA: Association for Computing Machinery,            research field is the security and dependability
     2017, p. 129–142. [Online]. Available: https://doi.org/10.1145/         of computer systems, with a particular focus on
     3050748.3050763                                                         trusted computing. He was principal investigator
[10] S. Fei, Z. Yan, W. Ding, and H. Xie, “Security vulnerabilities          of European research projects on IT security.
     of sgx and countermeasures: A survey,” ACM Comput.
     Surv., vol. 54, no. 6, jul 2021. [Online]. Available: https:
     //doi.org/10.1145/3456631
[11] C. Göttel, R. Pires, I. Rocha, S. Vaucher, P. Felber, M. Pasin,
     and V. Schiavoni, “Security, performance and energy trade-offs of
     hardware-assisted memory protection mechanisms,” in 2018 IEEE
     37th Symposium on Reliable Distributed Systems (SRDS), 2018, pp.
     133–142.
[12] A. Akram, A. Giannakou, V. Akella, J. Lowe-Power, and S. Peisert,
     “Performance analysis of scientific computing workloads on
     general purpose tees,” in 2021 IEEE International Parallel and
     Distributed Processing Symposium (IPDPS), 2021, pp. 1066–1076.
[13] S. Mofrad, F. Zhang, S. Lu, and W. Shi, “A comparison study of
     intel sgx and amd memory encryption technology,” ser. HASP ’18.
     New York, NY, USA: Association for Computing Machinery, 2018.
     [Online]. Available: https://doi.org/10.1145/3214292.3214301
[14] “Common        Terminology      for    Confidential   Computing,”
     Confidential Computing Consortium, Jan. 2024, [Online].
     Available:         https://confidentialcomputing.io/wp-content/
     uploads/sites/10/2023/03/Common-Terminology-for-
     Confidential-Computing.pdf.
[15] “Microbenchmark of Intel CPU 8375C,” CPU Benchmarks, Dec.
     2023, [Online]. Available: https://www.cpubenchmark.net/cpu.
     php?cpu=Intel+Xeon+Platinum+8375C+%40+2.90GHz.
[16] “Microbenchmark of Intel CPU 8480,” CPU Benchmarks, Dec.
     2023, [Online]. Available: https://www.cpubenchmark.net/cpu.
     php?cpu=Intel+Xeon+Platinum+8375C+%40+2.90GHz.
[17] “Microbenchmark of AMD EPYC 7763,” CPU Benchmarks, Dec.
     2023, [Online]. Available: https://www.cpubenchmark.net/cpu.
     php?cpu=Intel+Xeon+Platinum+8375C+%40+2.90GHz.


                                                                             Luigi Romano PhD, is a Full Professor at the
                                                                             University of Naples Parthenope. His research
                       Luigi Coppolino PhD, is an Associate Professor        interests are system security and dependability,
                       at the University of Naples Parthenope, Italy.        with focus on Critical Infrastructure Protection.
                       His research activity mainly focuses on               He has worked extensively as a consultant for
                       dependability of computing systems, critical          industry leaders in the field of security- and
                       infrastructure protection, and information            safety-critical computer systems. He was one
                       security. He was the technical coordinator of         of the members of the ENISA expert group on
                       the EC funded research project COMPACT and            Priorities of Research On Current and Emerging
                       involved with key roles in several others.            Network Technologies (PROCENT).




                       Salvatore D’Antonio is an Associate Professor
                       at the University of Naples Parthenope, Italy.
                       He is an expert in network monitoring, network
                       security and critical infrastructure protection.
                       He was the Coordinator of two EU research
                       projects on critical infrastructure protection,
                       namely INSPIRE and INSPIRE-INCO.




                       Davide Iasio is a Software Engineer at
                       Trust Up srl. His background includes the
                       development of microservices-based solutions
                       for data protection in cloud environments and the
                       management of cloud infrastructures.
