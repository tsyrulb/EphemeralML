                                                                                                                                   PDF Download
                                                                                                                                   3533737.3535098.pdf
                                                                                                                                   29 January 2026
                                                                                                                                   Total Citations: 36
                                                                                                                                   Total Downloads: 6446
    .
    .
        Latest updates: hps://dl.acm.org/doi/10.1145/3533737.3535098




                                                                                                                                   .
                                                                                                                                   .
                                                                                                                         Published: 12 June 2022
        .
        .
                                                                                                                         .
    RESEARCH-ARTICLE




                                                                                                                         .
                                                                                                                         Citation in BibTeX format
    Benchmarking the Second Generation of Intel SGX Hardware




                                                                                                                         .
                                                                                                                         .
                                                                                                                         SIGMOD/PODS '22: International
                                                                                                                         Conference on Management of Data
    MUHAMMAD EL-HINDI, Technical University of Darmstadt, Darmstadt, Hessen, Germany                                     June 13, 2022
    .
                                                                                                                         PA, Philadelphia, USA
    TOBIAS ZIEGLER, Technical University of Darmstadt, Darmstadt, Hessen, Germany




                                                                                                                         .
                                                                                                                         .
                                                                                                                         Conference Sponsors:
    .
    MATTHIAS HEINRICH, Technical University of Darmstadt, Darmstadt, Hessen, Germany                                     SIGMOD
    .
    ADRIAN LUTSCH, Technical University of Darmstadt, Darmstadt, Hessen, Germany
    .
    ZHEGUANG ZHAO, Technical University of Darmstadt, Darmstadt, Hessen, Germany
    .
    CARSTEN BINNIG, Technical University of Darmstadt, Darmstadt, Hessen, Germany
    .
    .
    .
    Open Access Support provided by:
    .
    Technical University of Darmstadt
    .
                                                    DaMoN '22: Proceedings of the 18th International Workshop on Data Management on New Hardware (June 2022)
                                                                                                                         hps://doi.org/10.1145/3533737.3535098
                                                                                                                                            ISBN: 9781450393782
.
    Benchmarking the Second Generation of Intel SGX Hardware
              Muhammad El-Hindi                                                   Tobias Ziegler                             Matthias Heinrich
       Technical University of Darmstadt                            Technical University of Darmstadt                Technical University of Darmstadt

                    Adrian Lutsch                                               Zheguang Zhao                                  Carsten Binnig
      Technical University of Darmstadt                             Technical University of Darmstadt                Technical University of Darmstadt

ABSTRACT                                                                                      already seen wide adoption for many different use cases including
In recent years, trusted execution environments (TEEs) such as Intel                          Database Management Systems (DBMSs). To enable secure exe-
Software Guard Extensions (SGX) have gained a lot of attention in                             cution, Intel SGX provides special CPU instructions for defining
the database community. This is because TEEs provide an interest-                             private memory regions in which the security of data is guaranteed
ing platform for building trusted databases in the cloud. However,                            by the hardware [12, 27, 38]. Even the operating system has no
until recently SGX was only available on low-end single socket                                access to these so-called enclaves.
servers built on the Intel Xeon E3 processor generation and came                                 SGX has many limitations for DBMSs. However, until re-
with many restrictions for building DBMSs. With the availability of                           cently SGX was only available in consumer-grade CPUs based
the new Ice Lake processors, Intel provides a new implementation                              on the previous Intel Xeon E3 processor generation. In addition to
of the SGX technology that supports high-end multi-socket servers.                            the low core count of these CPUs, SGX enclaves came with drastic
With this new implementation, which we refer to as SGXv2 in this                              technical limitations, such as a limited memory capacity of up to
paper, Intel promises to address several limitations of SGX enclaves.                         256 MB and significant performance overheads. The capacity re-
This raises the question whether previous efforts to overcome the                             strictions especially limited the application of Intel SGX for DBMSs.
limitations of SGX for DBMSs are still applicable and if the new                              In consequence, researchers in the database community started to
generation of SGX can truly deliver on the promise to secure data                             explore different ways to overcome these limitations, e.g., by only
without compromising on performance. To answer this question,                                 placing certain DBMS components inside an enclave [39] or design-
in this paper we conduct a first systematic performance study of                              ing enclave-native engines for this restricted environment [20, 33].
Intel SGXv2 and compare it to the previous generation of SGX.                                    SGXv2 lifts the major limitations. With the availability of the
                                                                                              new Intel Ice Lake processors [15], Intel promises to address several
ACM Reference Format:
                                                                                              limitations of SGX enclaves. The latest implementation of Intel SGX
Muhammad El-Hindi, Tobias Ziegler, Matthias Heinrich, Adrian Lutsch,
                                                                                              on these processors (in the following referred to as SGXv2), not
Zheguang Zhao, and Carsten Binnig. 2022. Benchmarking the Second Gen-
eration of Intel SGX Hardware. In Data Management on New Hardware                             only reduced the overhead of memory protection, but also increased
(DaMoN’22), June 13, 2022, Philadelphia, PA, USA. ACM, New York, NY, USA,                     the capacity of the protected memory region to up to 512 GB per
8 pages. https://doi.org/10.1145/3533737.3535098                                              socket (depending on the CPU model) [17]. This allows DBMSs to
                                                                                              hold even large data sets fully in the enclaves. In addition to that,
1     INTRODUCTION                                                                            the new scalability enhancements now allow DBMSs that use Intel
                                                                                              SGXv2 to scale across multiple sockets of high-end servers.
Trusted Execution Environments (TEEs). Trusted Execution En-
                                                                                                 The need to benchmark SGXv2 for DBMSs. This raises the
vironments have gained a lot of attention [4, 5, 8, 10, 11, 20, 29,
                                                                                              question whether previous efforts to overcome the limitations of
31, 33, 37, 44] in recent years because they enable trusted process-
                                                                                              SGX for DBMSs are still applicable and if the new generation of
ing of private data. As such, TEEs can be used to build trusted
                                                                                              SGX processors can truly deliver on the promise to secure data
databases [31, 32] that guarantee the confidentiality and integrity
                                                                                              without compromising on performance. To answer this question,
of data even when hosted by a third party. This is particularly in-
                                                                                              as a first contribution, we perform a systematic performance study
teresting when storing company data in public cloud environments
                                                                                              of Intel SGXv2 and compare it to the previous generation of SGX
rather than on-site. As TEEs fully protect data during processing,
                                                                                              (referred to as SGXv1 in this paper). In particular, we evaluate
this secures data from manipulation by even privileged users such
                                                                                              the performance of Intel SGXv2 for typical data access patterns
as administrators.
                                                                                              of OLTP and OLAP workloads. Moreover, as a second contribu-
   Intel SGX as important TEE technology. Today, different im-
                                                                                              tion we discuss lessons learned for building the next generation of
plementations of TEEs exist such as Intel SGX [27], ARM Trust-
                                                                                              high-performance enclave-based DBMSs on SGXv2. While the new
Zone [2] and several others [6, 18]. Among those, Intel SGX has
                                                                                              SGXv2 enhancements also cover several new security aspects, we
Permission to make digital or hard copies of all or part of this work for personal or         will solely focus on performance characteristics in this paper.
classroom use is granted without fee provided that copies are not made or distributed            In the following, we first briefly review the basics of Intel’s SGX
for profit or commercial advantage and that copies bear this notice and the full citation
on the first page. Copyrights for components of this work owned by others than ACM
                                                                                              (SGXv1 and SGXv2). Afterwards, we present the results of our
must be honored. Abstracting with credit is permitted. To copy otherwise, or republish,       evaluation study and the findings of our performed benchmarks.
to post on servers or to redistribute to lists, requires prior specific permission and/or a
fee. Request permissions from permissions@acm.org.
DaMoN’22, June 13, 2022, Philadelphia, PA, USA
© 2022 Association for Computing Machinery.
ACM ISBN 978-1-4503-9378-2/22/06. . . $15.00
https://doi.org/10.1145/3533737.3535098
DaMoN’22, June 13, 2022, Philadelphia, PA, USA                                                                                  M. El-Hindi, et al.



                        NUMA Node 0                NUMA Node 1            software. As part of this process, the system software copies data
                  PRM                    RAM                              from outside the PRM into the EPC and assigns the EPC pages to
                                                                          the created enclave. Thereby, the entire content of the enclave plus
                    EPC                          RAM
         CPU         Trusted ECALL Untrusted               CPU            some metadata is cryptographically hashed by the CPU. This hash
          Cache                                                           is called the measurement hash and can be used to attest that the
                       SW             SW
                                 OCALL                                    expected code is running inside the enclave [38].
                                                         UPI                 Trusted and untrusted SW interact through so-called E- and
                                                                          OCALLs. In order to transfer the control flow to code inside the
                                                                          EPC, untrusted software performs ECALLs (enclave calls). Similarly,
         Figure 1: Intel SGX multi-socket architecture
                                                                          trusted software can transfer the control flow back to code outside
                                                                          the enclave by means of OCALLs. These interactions not only repre-
                                                                          sent a context switch in the CPU, but they involve additional steps
2     BACKGROUND
                                                                          to preserve confidentiality of enclave data, such as flushing CPU
In the following we discuss the most important building blocks of         caches and the address translation cache (TLB) [30, 36, 41].
the Intel SGX technology and the latest enhancements that were               In our evaluation, we do not focus on the overhead of the inter-
introduced by the second generation of Intel SGX.                         action between trusted and untrusted parts of an application, but
                                                                          instead we concentrate on the overhead that comes from using data
2.1     Intel SGX Overview                                                within the EPC. The reason is that SGXv2, which we discuss next,
Intel SGX is a hardware-based TEE technology. It introduces new           provides much higher EPC capacities which potentially allows a
platform extensions such as a Memory Encryption Engine (MEE)              DBMS to hold all data structures fully inside the enclave (i.e., much
and new CPU instructions (SGX1 and SGX2 [26, 42]) to enable appli-        less interactions with untrusted code are needed).
cations to create private memory regions protected from privileged
software. That means that even the operating system or hypervisor
are not allowed to access these regions. To create these so-called        2.2    Second Generation Intel SGX
enclaves, SGX reserves a portion of the memory called the Proces-         In this paper, we focus on SGXv2 that was introduced with the
sor Reserved Memory (PRM), as depicted in Figure 1. The size of           launch of the new Intel Ice Lake processors. With SGXv2, Intel
the PRM is configured in the BIOS and will not be available to the        introduced several enhancements to the SGX technology such as
operating system. As shown in Figure 1, inside the PRM Intel SGX          an increased EPC capacity (from previously 256 MB to up to 512 GB
maintains the Enclave Page Cache (EPC) that stores code and data          per socket). Further, Intel SGX now also supports running enclaves
of enclaves in 4 KB memory pages. These pages are encrypted and           on multi-socket server systems. However, to the best of our knowl-
their data is only decrypted when it is loaded into the CPU cache         edge, little is known about the implementation details of these
for processing. Furthermore, EPC pages are integrity protected to         enhancements. Hence, in the following, we will only give a brief
prevent unnoticed manipulation of the data. [38]                          overview of the new enhancements based on [17] and then focus
   Software (SW) (i.e., applications) that runs inside an enclave is      on empirically evaluating these enhancements in Section 3.
referred to as trusted SW or trusted code. Intel SGX guarantees that         Increased EPC capacity. In order to increase the memory ca-
only code from within the same enclave has access to the EPC pages        pacity available to enclaves, Intel SGX reworked its encryption
of that enclave. Any code that is running outside the PRM, i.e., in the   and integrity protection mechanism. Instead of the MEE, SGX now
untrusted memory region, is prevented from accessing pages in the         uses Intel’s Total Memory Encryption (TME) technology to protect
PRM. This is achieved with the help of hardware address translation       the confidentiality of data. While Intel mentions that TME relies
by making sure that the virtual-to-physical address mapping is only       on AES-XTS [25] as a block cipher mode, no detailed information
accessible to the owning enclave. Hardware address translation also       about the integration of Intel SGX with TME is available. Yet, Intel
enables enclave developers to assign a heap size larger than EPC to       TME is undoubtedly one major building block for supporting larger
their application (by setting a HeapMaxSize config parameter) [16].       EPC sizes. At the same time, new ways are used to guarantee data
However, exceeding EPC capacity does not come without cost as             integrity and protect against replay attacks which might introduce
explained next.                                                           additional overheads. For instance, error correction codes are used
   Since enclave memory is a finite resource, Intel SGX comes with        to detect manipulations of data from outside the enclave. Similarly,
a mechanism to swap the encrypted EPC pages out to unprotected            a trusted firewall has been introduced to prevent manipulations of
memory (and vice versa). This mechanism is also referred to as            data from a malicious enclave inside the EPC.
paging. In order to protect the integrity of pages and to ensure that        Multi-socket support. Previously, Intel SGX was only available
only the latest version of an evicted EPC page can be loaded back,        on single-socket servers. With the introduction of SGXv2, however,
SGX stores version information in a version array that is stored          Intel SGX is also available on multi-socket systems that utilize a
in EPC pages. The additional integrity protection as well as the          Non-Uniform Memory Access (NUMA) memory architecture. For
required context switch and data transfer makes EPC paging very           this, two major challenges had to be addressed: First, in SGXv1
expensive as already discussed by previous work on SGXv1 [30, 35].        encryption keys and certificates were derived from per CPU socket
   The first step towards using and interacting with an enclave           secrets. However, in case of multiple CPUs it is required to share a
is enclave creation and initialization. During enclave creation the       common key across sockets to allow CPUs to access EPC pages that
initial code and data of the enclave is loaded by untrusted system        were encrypted by a different CPU [17]. Second, and more relevant
Benchmarking the Second Generation of Intel SGX Hardware                                                                       DaMoN’22, June 13, 2022, Philadelphia, PA, USA


          Table 1: Properties of experiment hardware                                                   3M
                                                                                                                                                                SGXv1




                                                                                operations [ops/sec]
                                                                                                                                                                SGXv2

                                     SGXv1                 SGXv2                                       2M


        Architecture             Cascade Lake         Ice Lake
        #Sockets                        1                 2                                            1M                               SGXv2 remote NUMA
                                                                                                                                                            SGXv2 paging
        CPU                      Xeon E-2288G      Xeon Gold 6326                                            SGXv1 paging
        Core Count                      8                16                                             0                           X
        CPU frequency (max)         5.0 GHz           3.5 GHz                                               0B              50 GB               100 GB       150 GB
                                                                                                                                    database size
        L1 d/i cache              256/256 KiB       1.5/1.0 MiB
        L2 cache                     2 MiB             40 MiB
        LLC cache                    16 MiB            48 MiB            Figure 2: Throughput of a 80% read / 20% insert workload in
        EPC (per socket)            128 MB             64 GB             a B-Tree. A significant performance improvement is observ-
        DRAM (per socket)           128 GB             256 GB            able for larger database sizes in SGXv2.

in our context, protected memory that is allocated on one socket
needs to be securely accessible to the remote CPU. In the following,     group of experiments, we present several findings with regard to
we elaborate on this challenge in more detail.                           the usage of multiple concurrent enclaves in SGXv2 that can result
    In a NUMA architecture, local memory is provided for each            from running different DBMS instances on the same hardware.
processor as depicted in Figure 1. Each CPU resides on a separate           Setup. For our study, we use one SGXv1 and one SGXv2 server.
NUMA node (i.e. socket) which are connected via a fast interconnect      The hardware characteristics of both systems are shown in Table 1.
(the Ultra Path Interconnect (UPI) on Intel platforms) to support        To make our experiments reproducible over several runs, we con-
memory access from remote CPUs. To securely access data of EPC           figured both servers to always use their maximum CPU frequency.
pages on a remote NUMA node, SGXv2 introduces an additional              Note that, while SGXv2 could in principle support 512 GB of EPC,
UPI Crypto Engine (UCE) that protects the confidentiality of data        our CPU model only support a maximum EPC capacity of 64 GB
transferred over UPI.                                                    per socket (i.e., 128 GB in total).
    To avoid overhead for untrusted Software, SGXv2 extends the             The comparison of the plain hardware characteristics as shown
memory coherence architecture as follows: When a core on one             in Table 1 indicates a significant improvement for applications
socket (e.g., the left one) incurs a cache miss, the referenced memory   running on SGXv2. At the same time, the hardware differences make
address is passed on to a local caching agent. The agent knows           it difficult to perform a direct comparison of SGXv1 and SGXv2.
which physical memory addresses are attached to which socket and         Hence, in the following, we mainly study the characteristics of
is in charge of forwarding the requests via UPI to the remote socket     SGXv2 and only include results for SGXv1 when appropriate.
if necessary. When protected memory is requested, the request is
sent with a so-called secure attribute to the UCE for encryption. In     3.1    Data Scalability
contrast, requests for unprotected memory are passed on in plain         In the first set of experiments, we evaluate SGXv2 with regard to
text. The receiving side will forward the request to its local Caching   growing data set sizes and compare it to SGXv1. Moreover, since
Agent. If a request references data in protected memory, the agent       SGXv2 supports multiple sockets, it allows enclaves to grow across
will check if the secure attribute has been set and only then forward    NUMA boundaries. Therefore, we also study typical NUMA effects
the request to its memory controller. Subsequently, the retrieved        that play an important role in modern DBMSs [9, 19].
cache line is forwarded to the UCE for protected transmission of            Performance for growing data sizes. In order to evaluate to
the cache line to the requesting socket.                                 which extent SGXv2 supports larger amounts of data, we imple-
    The example indicates an additional overhead for enclaves when       mented a B-Tree index structure as a trusted library inside SGX.
accessing memory on remote NUMA nodes. That means, that de-              We use it to execute a YCSB-like workload with 20% inserts and
spite the regular overhead of cross NUMA communication, Intel            80% reads to gradually increase the size of the database. The results
SGX introduces even further overhead, e.g., because of the addi-         of this experiment are shown in Figure 2. As expected, the perfor-
tional encryption. Due to the recent availability of this hardware,      mance of the B-Tree on SGXv1 (red line) drops very quickly (after
however, no empirical evaluation of this overhead has been per-          128 MB) and only supports a total database size of up to 64 GB due
formed yet. This motivated us to include experiments for analyzing       to the corresponding limit on enclave sizes in SGXv1. In contrast
the NUMA effects on SGXv2 in our evaluation.                             to that, the B-Tree in the SGXv2 enclave (blue line) shows orders of
                                                                         magnitude better performance for much larger database sizes.
3    EXPERIMENTAL EVALUATION                                                Moreover, in the case of SGXv2 we can observe two performance
In the following, we perform several experiments to understand the       drops when scaling the data size: The first performance drop is
characteristics and pitfalls of the second generation of Intel SGX       at around 64 GB, when the data size reaches the capacity limit of
hardware. Where applicable, we also compare and relate to known          the EPC on the first NUMA node. The second performance drop
characteristics of the first generation of SGX.                          happens at around 128 GB where the capacity of the EPC on the
   In the first set of experiments we take a look at the performance     second NUMA node is reached. At this point, similar to SGXv1, we
for growing data set sizes. Afterwards, we study the performance         can observe a drastic performance penalty due to paging. In the
of SGXv2 for basic OLTP and OLAP workload patterns. In the last          following, we will have a closer look at these two effects.
DaMoN’22, June 13, 2022, Philadelphia, PA, USA                                                                                   M. El-Hindi, et al.


Table 2: Local and cross NUMA access latencies [CPU cycles]
                                                                                   60K                            ratio   99.9th perc.




                                                                          cycles
                                Untrusted             Trusted                                                      1:1      1645.177
                                                                                   40K
                                 Latency         Latency Overhead                                                  1:2     68790.278
          Local NUMA              367.7646       486.1015   32.2%                  20K                             1:4    101569.258
          Cross NUMA              568.6215       832.1615   46.3%                                                  1:8    155954.108
                                                                                     0
        Rel. NUMA penalty          54.6%          71.1%                                     1:1   1:4   1:16      1:16    218224.092
                                                                                         EPC (8GB) to data size

                                                                          Figure 3: Paging overhead in CPU cycles. To enforce paging,
   Cost of crossing NUMA boundaries. In Figure 2, we can ob-
                                                                          we use a data set size that is a multiple of the EPC (e.g., 1:4
serve that the performance of our B-Tree decreases for the first time
                                                                          means 4× the EPC capacity of 8 GB(=32 GB)).
when the data size exceeds the EPC capacity of the NUMA node
to which the process was pinned. In consequence, new data must
be stored in EPC pages that are allocated on the remote NUMA
node. While the importance of NUMA awareness to overall system               Cost of Paging. In SGXv2, paging is similarly expensive as in
performance is a known issue [9, 19], it is unclear what overhead         SGXv1 as evidenced by the second performance drop in Figure 2.
is added by SGXv2 and its additional encryption of UPI traffic.           However, it is unclear how the overhead changes for growing data
   Hence, in the next experiment, we measure the latencies for            set sizes in SGXv2. To show the impact of paging on memory access
accessing memory on the local and remote NUMA node in CPU                 latencies in SGXv2, we varied the data set size. To enforce paging,
cycles. For this, we pin the process to the first NUMA node using         we reduced the PRM in the BIOS to 8 GB and use data set sizes
numactl. Since the libnuma library is not available for use inside        that are multiples of the EPC, i.e., 4× and 16× (shown as ratios 1:4
the enclave, we apply the following approach for allocating memory        and 1:16 in the figure). As a baseline, we use a configuration which
on the remote NUMA node: Since memory is first allocated on the           uses data of the same size as the EPC, ie. 8 GB (shown as 1:1). As
NUMA node to which a process is pinned to, we pre-allocate a              before, we ensure that we can measure the latency of page faults
large chunk of 70 GB inside the enclave to consume more than the          by traversing a randomly linked list of memory-aligned nodes of
EPC capacity on the first NUMA node. This forces any subsequent           4 KB. The results are shown in Figure 3.
memory allocation to happen on the remote NUMA node.                         We can observe that paging increases the latency by around
   To measure the memory access latencies that involve the remote         two orders of magnitude when comparing 1:1 and 1:4. Surprisingly,
NUMA node, we allocate another 2 GB memory buffer (which is               when increasing the ratio even further to 1:16, the latencies seem to
then allocated in the second NUMA node). The data in this region          be affected only minimally. Yet, when looking at the tail latencies
is organized as a randomly linked list. This allows us to perform a       (right side of Figure 3), the impact becomes more apparent. As
(random) scan over the data while avoiding that the out-of-order          shown in the table, the tail latency doubles when comparing ratio 1:4
execution schedules memory loads in parallel, which would distort         and 1:16. Obviously, these higher tail latencies have a tremendous
the memory access latencies. For NUMA local access measurements,          impact on the DBMS performance (in particular for OLTP).
we of course skip the previous pre-allocation step to make sure              Another interesting question is to which extent the paging over-
that the buffer is fully located on the first NUMA node. For the          head influences typical OLAP-style workloads. To show this, we
untrusted baseline we use the numactl tool to pin the process to          further evaluate the effect of paging on sequentially scanning data.
the first NUMA node while binding the memory allocation to the            Figure 4a shows that SGXv2 can maintain a steady performance
second node and thus enforcing cross NUMA accesses.                       for sequentially scanning data while the performance of SGXv1
   Table 2 shows the average latency for local NUMA and remote            quickly drops after reaching the EPC limit due to paging.
NUMA memory accesses. We start discussing the table row-by-row.              In the previous experiments we allocated the data directly inside
Comparing untrusted to trusted local NUMA access, we can see              the enclave. In the next experiment, we study the effect of paging
that local memory access in the enclave has a clear latency over-         on copying data that needs to be transferred into the enclave. Intel
head of around 30 %. This overhead is most likely caused by the           SGX provides two mechanisms to give enclaves access to data
necessary decryption of EPC pages when loading data into the CPU          residing outside the enclave. In our experiment we use the in/out
cache [12, 38]. When looking at cross NUMA access latencies, we           mode which allocates EPC pages inside the enclave and copies
can observe that accessing remote memory in an enclave has an             the requested data from untrusted memory. This is in contrast to
even higher overhead compared to the untrusted baseline. To quan-         the user_check mode which provides direct (i.e. without copying),
tify the penalty of accessing a remote NUMA compared to local             but unprotected access to untrusted memory. As can be seen in
NUMA, we now look at the last row of Table 2. Thereby, we view            Figure 4b, for small amounts of data the performance pattern of
the untrusted and trusted case in isolation. While it is evident from     SGXv1 and SGXv2 is comparable since the context switch overhead
Table 2 that cross NUMA accesses are expensive even for the un-           dominates. Once this overhead has been amortized, the variable
trusted baseline, the penalty for trusted code is disproportionately      cost of data copying becomes the dominant factor. Further, the
high with around 71%. Based on the few information provided by            bandwidth of SGXv1 is severely reduced for small data sizes once
Intel in [17], we speculate that this overhead can be attributed to the   paging kicks in. This is not the case for SGXv2 due to the increased
additional encryption of UPI traffic for trusted memory accesses.         EPC capacity.
Benchmarking the Second Generation of Intel SGX Hardware                                                                                     DaMoN’22, June 13, 2022, Philadelphia, PA, USA

        bandwidth [GB/s]




                                                                                                        performance relative
                                                                                                                               0.75




                                                                                                            to untrusted
                           2
                                                                    untrusted SGXv1
                                                                                                                               0.50
                           1
                                   SGXv1
                                   SGXv2                                                                                       0.25
                                           8 MB           134 MB         2 GB          34 GB
                                                     table size (log)                                                          0.00
                                                                                                                                      5%R 95%W    50%R 50%W       95%R 5%W
                                   (a) Sequential scan of varying data sizes                                                                       workload
        bandwidth [GB/s]




                           2.0
                                                                                               Figure 5: Relative performance of various YCSB-like work-
                           1.5
                                                                                               loads in SGXv2 compared to an untrusted baseline. SGXv2
                           1.0                                                                 has only a relatively small overhead across all workloads.
                           0.5             SGXv1
                                           SGXv2
                                 4 kB      64 kB   1 MB     8 MB   134 MB       2 GB   34 GB   contains more CPU-intensive operations because it generates ran-
                                                   transferred data (log)
                                                                                               dom 128 byte values as updates. Since CPU-intensive operations
        (b) Secure data copy to an enclave for various data sizes                              have similar to identical performance inside and outside enclaves,
                                                                                               they mask the impact of memory access latencies overall.
Figure 4: Effect of paging on a sequential scan (a) and on                                        Summary. Comparing the performance of our data-intensive
copying data securely to an enclave (b). In contrast to SGXv1,                                 workload between untrusted and trusted execution, we saw a max-
SGXv2 is not affected by paging due to its larger EPC capac-                                   imum performance reduction of approximately 25 % when all the
ity.                                                                                           data fits into the EPC. We conclude that for many use cases requir-
                                                                                               ing the security of a TEE, this is probably a good trade off.

                                                                                               3.3    Overhead of Trusted I/O
   Summary. With regard to data scalability, we observed that the
                                                                                               In addition to accessing data in memory, DBMSs also need to access
increased EPC of SGXv2 enables database engines running inside
                                                                                               and store data on disk for purposes like recovery. Therefore, in
enclaves to use orders of magnitude more memory. This allows to
                                                                                               this experiment we look at two different flavors of enabling trusted
store more data inside an enclave and to copy larger chunks of data
                                                                                               I/O in SGXv2: sgx_fwrite and sgx_seal_data. With sgx_fwrite
with one enclave call, which makes SGX more practical for building
                                                                                               the Intel Protected File System Library [14] provides the trusted
database engines. While the new NUMA support allows enclaves to
                                                                                               equivalent to fwrite for writing binary streams. Using this func-
span multiple NUMA nodes, developers should pay attention to the
                                                                                               tion, data is encrypted and integrity protected before being written
additional overhead of memory accesses across NUMA regions and
                                                                                               to an untrusted disk. In contrast to sgx_fwrite, sgx_seal_data
to the lack of a fine-grained control of NUMA allocation due to the
                                                                                               does not perform file I/O, but only encrypts and integrity protects
missing libnuma library inside SGX. Finally, although the amount
                                                                                               the data. Hence, an additional interaction with untrusted code to
of memory usable by enclaves has been increased significantly, the
                                                                                               perform file I/O is required (OCALL). To ensure that data is written
cost of paging is still tremendous and must be considered when
                                                                                               to disk, we use fflush and its trusted counterpart sgx_fflush.
data exceeds the total EPC capacity.
                                                                                                  In Figure 6 we show the effect of various I/O sizes on the normal-
                                                                                               ized CPU utilization (cycles/byte). We compare the two secure I/O
3.2    Trusted SGXv2 vs. Untrusted                                                             variants with untrusted file I/O (we use fwrite because it resembles
In the previous experiment we identified two critical factors which                            sgx_fwrite). All three variants have in common that larger I/O
impact performance, i.e., remote NUMA access and paging. In this                               sizes significantly reduce CPU utilization because most overhead is
experiment we instead shed light on the overhead of trusted SGXv2                              per function call, not per byte. Surprisingly, sgx_fwrite is much
vs. untrusted execution. To that end, we execute a YCSB-like bench-                            more expensive than sgx_seal_data. In fact, when writing only
mark with varying read/write (update) ratios where all data fits into                          2 bytes sgx_fwrite spends 20× more cycles than sgx_seal_data
the available EPC capacity. This avoids effects like paging which                              (note the log-scale on the y-axis). This initial function call overhead
we analyzed before. Moreover, we use the same B-Tree as in the                                 of sgx_fwrite can be partially amortized by writing larger I/O
first experiment, however, we populate it with 10 M key-value pairs                            sizes at once. However, even with large batch writes sgx_fwrite is
(using 8 B for keys and 128 B for values).                                                     at best 4× more expensive than sgx_seal_data. We regard a more
    Figure 5 shows the performance of SGXv2 relative to the un-                                in-depth analysis of the differences between both protected file I/O
trusted baseline. We can observe that the read-heavy workload                                  strategies as future work.
appears to have a higher overhead than the write-heavy workload.                                  Summary. Our key insight is that the choice of the protected I/O
This effect can be explained by comparing both workloads in depth.                             library can impact performance heavily. Moreover, regardless of the
As discussed in Section 3.1, the main overhead of SGXv2 stems                                  I/O strategy, we can see that larger I/O sizes burn less cycles per byte.
from higher memory access latencies. The read-heavy workload                                   For DBMS designs based on SGXv2 this means that optimizations
is dominated by memory loads and therefore highly impacted by                                  such as group commit are important to collect enough log entries
these increased latencies. In contrast, the write-heavy workload                               before flushing.
DaMoN’22, June 13, 2022, Philadelphia, PA, USA                                                                                                                                                                                                                  M. El-Hindi, et al.




                                                                                                                                                                                 operations [ops/sec]
                                                                           sgx_fwrite                     sgx_seal_data+OCALL                   untrusted (fwrite)                                      3M
      I/O cost [cycles/byte] (log2)


                                                                                                                                                                                                                                                                      e0
                                                                     147087                                                                                                                                                                                           e1
                                                                                                                                                                                                        2M                                                            e2
                                      16384                               9385.3                            7417.5

                                                                                                                                                                                                        1M       baseline (isolated enclave)
                                                                                  708.2
                                              512                                                                463.4                           346.5                                                                                                           X     X
                                                                                       61.5                                                                                                                                                                      X
                                                                                                                                                                                                         0
                                                                                                                     30.9                                                                                    0                     10000                20000
                                                                                                  13.8                                               21.8
                                                      16                                                                    4.9
                                                                                                                                                                                                                                       time [seconds]
                                                                                                                                        3                   4
                                                                                                   12.5                                                         1.7
                                                                                                                                                                      1.5
                                                                                                                                  2.8

                                                                     32 B 2 kB 131 kB8 MB                  32 B 2 kB 131 kB8 MB                 32 B 2 kB 131 kB8 MB        Figure 8: Performance of 3 concurrently running enclaves
                                                                                                                 I/O size                                                   executing the same workload as in Figure 2. When the ag-
                                                                                                                                                                            gregated size of the enclaves exceeds the total EPC, the per-
Figure 6: Effect of I/O on CPU utilization in cycles/byte of                                                                                                                formance of all enclaves starts to become unpredictable.
the two trusted I/O variants (sgx_fwrite and sgx_seal_data)
vs. untrusted I/O (fwrite).
                                                                                                                                                                            the same server. For this experiment we create three enclaves with
                                                                                                                                                                            a HeapMaxSize setting of 64 GB, i.e., each enclave is guaranteed to
                                       creation time [min.]




                                                              10.0
                                                                      ●
                                                                            SGXv1                               remote NUMA
                                                                                                                                            ●
                                                                                                                                                                            occupy the total EPC of a NUMA node. All enclaves are started con-
                                                               7.5    ●
                                                                            SGXv2
                                                                                                                                                                            currently and run the same B-Tree insertion workload as introduced
                                                               5.0                                                                                 paging
                                                                                                            X                                                               in Section 3.1. This means that the enclaves initially utilize only a
                                                               2.5                            ●             ●
                                                                                                                                                                            small fraction of their heap size, but their memory consumption
                                                                                   ●          ●


                                                               0.0
                                                                              ●
                                                                           ●● ●
                                                                          ●●●
                                                                          ●
                                                                                   ●
                                                                                                                                                                            increases as time passes. All three enclaves are pinned to the first
                                                                      0B                          50 GB              100 GB                 150 GB
                                                                                                          SGX heap size
                                                                                                                                                                            NUMA node using the numactl tool. The results of this experiment
                                                                                                                                                                            are depicted in Figure 8. For comparison, we additionally show the
                                                                                                                                                                            performance of only a single enclave running the same workload
Figure 7: Duration of enclave creation for varying heap sizes.
                                                                                                                                                                            in isolation (blue dashed line).
As soon as the heap size exceeds the EPC (≈ 64 GB in SGXv2),
                                                                                                                                                                                Based on Figure 8 we can make several interesting observations.
a significant increase in creation time can be observed.
                                                                                                                                                                            First, although all three enclaves are small in the beginning and fit
                                                                                                                                                                            into the EPC of the first NUMA node, the performance of the en-
3.4                                   Other Effects of Enclaves                                                                                                             claves is lower than the baseline; i.e., concurrently running enclaves
                                                                                                                                                                            affect each others performance. Second, as long as all enclaves fit
The increased EPC capacity offered by SGXv2 not only suggests
                                                                                                                                                                            into the EPC (regardless of the NUMA node), their performance
that more data can be stored inside an enclave, but it also provides
                                                                                                                                                                            behaves similarly. This indicates that all three enclaves are treated
the possibility to run multiple (larger) enclaves on a SGXv2 capable
                                                                                                                                                                            equally in terms of scheduling and memory allocation (the BIOS
system at the same time. This is especially interesting for cloud
                                                                                                                                                                            setting for SGX QoS is OFF). Third, due to the aggregated enclave
settings since not only larger data sizes can be kept in the enclave,
                                                                                                                                                                            sizes, the performance drops caused by remote NUMA access or
but also several DBMS instances could be run on the same SGXv2
                                                                                                                                                                            paging occur earlier. Fourth, once paging sets in, the performance
server.
                                                                                                                                                                            of the different enclaves becomes unpredictable. Only after the
    Creation Time of Enclaves. In this experiment, we investigate
                                                                                                                                                                            first enclave finishes execution (depicted by an X in the figure), the
the trade-off between the creation time and the size of the enclave
                                                                                                                                                                            performance of the other enclaves recovers due to more memory
(HeapMaxSize). Choosing an appropriate HeapMaxSize for the ap-
                                                                                                                                                                            being available. Moreover, once the two enclaves e0 and e1 finish
plication is important because when the HeapMaxSize is reached
                                                                                                                                                                            their execution, the performance of the last enclave e2 increases to
the application crashes on the next memory allocation (as shown
                                                                                                                                                                            the same level as the baseline.
in Figure 2). Therefore, we vary the HeapMaxSize and measure the
                                                                                                                                                                                Summary. Based on our experiments we observed that the cre-
time it takes to create the enclave in SGXv2. We fixed the value
                                                                                                                                                                            ation time of an enclave is not only affected by the size of the
for HeapMinSize to 65536 byte. Due to the support for dynamic
                                                                                                                                                                            enclave, but is also influenced by NUMA and paging effects. Fur-
memory allocation in Intel SGXv2, one would expect that the du-
                                                                                                                                                                            ther, we showed that concurrently running enclaves decreases the
ration of enclave creation is stable regardless of the HeapMaxSize
                                                                                                                                                                            performance of the enclaves and could even lead to unpredictable
setting. However, as can be seen in Figure 7, we observe that the
                                                                                                                                                                            performance when EPC capacity is exceeded. Both observations
enclave creation time increases significantly the more heap size is
                                                                                                                                                                            are important for scaling out databases (by spinning up additional
configured via the HeapMaxSize setting. More importantly, as the
                                                                                                                                                                            instances) or supporting concurrent customer workloads.
configured heap size exceeds the capacity of the local NUMA node,
we can observe an even stronger slowdown of enclave creation.
This suggests that in cases where an on-the-fly creation of enclaves                                                                                                        4   RELATED WORK
is required for DBMSs, extra caution should be applied. Especially                                                                                                          To the best of our knowledge, most related work revolves around
for larger enclave sizes it seems undesirable to create short running                                                                                                       SGXv1. These works cover several different areas from within and
on-the-fly enclaves.                                                                                                                                                        outside of the database community. In the following, we focus on
    Performance of Concurrent Enclaves. In this experiment, we                                                                                                              work that addresses the limitations of SGXv1, builds secure DBMSs
show the effect of running multiple DBMS instances in parallel on                                                                                                           for SGXv1 or studies the performance properties of SGXv1.
Benchmarking the Second Generation of Intel SGX Hardware                                                     DaMoN’22, June 13, 2022, Philadelphia, PA, USA


    Overcoming SGX limitations. Several previous work from the           step in the direction of designing efficient, reliable and secure data-
system community looked at how the overhead of context switches          base engines given the potentials of SGXv2. Prior work on secure
in SGXv1 (i.e., ECALL/OCALL) [30, 36, 41] or paging [22, 35] can         enclave databases mainly focused on the limitations of SGXv1 by,
be overcome. While these works present an in-depth view of the           e.g., only placing certain DBMS components inside the enclave. In
corresponding limitation, our work followed a broader focus to           contrast to that, we believe that the whole DBMS and its data can
identify new challenges for SGXv2 such as NUMA effects.                  be secured inside the enclave by using the advancements of SGXv2.
    Building enclave-enabled DBMSs. Studying Intel SGX from a            As such, the design of all DBMS core components needs to be revis-
data management perspective is another area that has attracted           ited to take the unique characteristics of SGXv2 into account, e.g.,
several research efforts. Besides works that discuss how Intel SGX       with regard to memory management (NUMA effects) and disk I/O
and TEEs in general can be used for trusted data processing [3, 11],     (logging).
recent work looked at how DBMS can be engineered to make use                Finally, we plan to refine the results of our study in several
of the capabilities of SGXv1 [4, 8, 10, 20, 31, 33, 44]. Our work        directions to provide a more comprehensive view about design-
instead focused on SGXv2 and showed that SGXv2 includes several          ing DBMSs for SGXv2. For instance, studying the effects of multi-
improvements that open up new opportunities for database design          threading, taking a closer look at the effect of cache misses and
and necessitate a re-evaluation of previous assumptions.                 analyzing the performance impact of enclave calls in more detail
    Analyzing performance properties. To gain more detailed in-          are important extensions of our work. Further, not only looking at
sights into the performance of SGXv1 applications, several works         concurrently running enclaves, but also studying the effect of un-
propose tools [21, 23, 34, 40] that can be used to measure different     trusted code running in parallel to an enclave is another interesting
performance aspects such as page faults and enclave transitions          direction for future work.
[21, 40]. Moreover, there has been work on studying the perfor-
mance of SGXv1 in different settings [1, 7, 43] such as virtualized      ACKNOWLEDGMENTS
environments [7] or comparing Intel SGX to other TEE technolo-
                                                                         This work was partially funded by the National Research Center
gies [28]. Most related to our paper are the works by Harnik et
                                                                         ATHENE, the BMWK project SafeFBDC (01MK21002K) and the
al. [13] and Maliszwski et al. [24]. While the former looks at the
                                                                         BMBF project TrustDBle (16KIS1267). We also thank the SAP HANA
performance of SGXv1 for different data encryption settings and
                                                                         team for the support.
related access patterns, the latter studies the performance of SGXv1
for join algorithms.
                                                                         REFERENCES
                                                                          [1] Ayaz Akram, Anna Giannakou, Venkatesh Akella, Jason Lowe-Power, and
                                                                              Sean Peisert. 2021. Performance Analysis of Scientific Computing Work-
                                                                              loads on General Purpose TEEs. In 2021 IEEE International Parallel and Dis-
5    CONCLUSIONS & FUTURE DIRECTIONS                                          tributed Processing Symposium (IPDPS). IEEE, Portland, OR, USA, 1066–1076.
                                                                              https://doi.org/10.1109/IPDPS49936.2021.00115
In this paper, we benchmarked the second generation of Intel SGX          [2] Thaynara Alves and D. Felton. 2004. Trustzone: Integrated Hardware and Soft-
(SGXv2) focusing on the question how this new generation might                ware Security. Information Quarterly 3, 4 (01 2004).
                                                                          [3] Nicolas Anciaux, Philippe Bonnet, Luc Bouganim, Benjamin Nguyen, Philippe
change the design of future secure DBMSs.                                     Pucheral, Iulian Sandu Popa, and Guillaume Scerri. 2019. Personal Data Manage-
    Main Findings. As a first finding, we showed that SGXv2 deliv-            ment Systems: The security and functionality standpoint. Information Systems
ers on its promise to improve the capacity of enclaves. Compared              80 (Feb. 2019), 13–35. https://doi.org/10.1016/j.is.2018.09.002
                                                                          [4] Panagiotis Antonopoulos, Arvind Arasu, Kunal D. Singh, Ken Eguro, Nitish
to SGXv1 the capacity is two to three orders of magnitude larger de-          Gupta, Rajat Jain, Raghav Kaushik, Hanuma Kodavalla, Donald Kossmann, Niko-
pending on the configuration. For example, in our setup we showed             las Ogg, Ravi Ramamurthy, Jakub Szymaszek, Jeffrey Trimmer, Kapil Vaswani,
that an in-memory B-Tree can scale up to about 120 GB of data and             Ramarathnam Venkatesan, and Mike Zwilling. 2020. Azure SQL Database Al-
                                                                              ways Encrypted. In Proceedings of the 2020 ACM SIGMOD International Con-
still provide high performance and that SGXv2 has only around 25 %            ference on Management of Data. ACM, Portland OR USA, 1511–1525. https:
overhead compared to a pure in-memory B-Tree. In contrast, this               //doi.org/10.1145/3318464.3386141
                                                                          [5] Stefan Brenner, Tobias Hundt, Giovanni Mazzeo, and Rüdiger Kapitza. 2017.
workload performs 25× worse in SGXv1 due to the limited capacity              Secure Cloud Micro Services Using Intel SGX. In Distributed Applications and
and the involved paging. Moreover, the support of SGXv2 in server-            Interoperable Systems, Lydia Y. Chen and Hans P. Reiser (Eds.). Springer Interna-
grade CPUs brings additional benefits like larger caches, higher              tional Publishing, Cham, 177–191.
                                                                          [6] Victor Costan, Ilia Lebedev, and Srinivas Devadas. 2016. Sanctum: Minimal
core counts, and scaling across NUMA regions. Therefore, we be-               Hardware Extensions for Strong Software Isolation. In 25th USENIX Secu-
lief that SGXv2 is a huge step towards building high performance              rity Symposium (USENIX Security 16). USENIX Association, Austin, TX, 857–
in-memory databases completely inside an SGX enclave.                         874. https://www.usenix.org/conference/usenixsecurity16/technical-sessions/
                                                                              presentation/costan
    However, using the Intel SGX technology still comes with several      [7] Tu Dinh Ngoc, Bao Bui, Stella Bitchebe, Alain Tchana, Valerio Schiavoni, Pascal
pitfalls. First, memory management needs to be designed carefully             Felber, and Daniel Hagimont. 2019. Everything You Should Know About Intel SGX
                                                                              Performance on Virtualized Systems. Proceedings of the ACM on Measurement
to take the additional overhead for, e.g., remote NUMA access into            and Analysis of Computing Systems 3, 1 (March 2019), 5:1–5:21. https://doi.org/
account. Second, our experiments indicate that different imple-               10.1145/3322205.3311076
mentations of trusted disk I/O can have performance differences in        [8] Saba Eskandarian and Matei Zaharia. 2019. ObliDB: oblivious query processing
                                                                              for secure databases. Proceedings of the VLDB Endowment 13, 2 (Oct. 2019),
orders of magnitude, requiring a careful choice of libraries and func-        169–183. https://doi.org/10.14778/3364324.3364331
tions. Finally, SGXv2 does not eliminate the performance penalty          [9] Frans Faerber, Alfons Kemper, Per-Ã. . . ke Larson, Justin Levandoski, Tjomas Neu-
of paging, but rather shifts it to larger memory sizes.                       mann, and Andrew Pavlo. 2017. Main Memory Database Systems. Foundations and
                                                                              TrendsÂ® in Databases 8, 1-2 (2017), 1–130. https://doi.org/10.1561/1900000058
    Future Work. While this paper provides a first systematic study      [10] Benny Fuhry, H A Jayanth Jain, and Florian Kerschbaum. 2021. EncDBDB:
on the basic aspects of SGXv2 as discussed before, it is only a first         Searchable Encrypted, Fast, Compressed, In-Memory Database Using Enclaves.
DaMoN’22, June 13, 2022, Philadelphia, PA, USA                                                                                                                 M. El-Hindi, et al.


     In 2021 51st Annual IEEE/IFIP International Conference on Dependable Systems         [28] Saeid Mofrad, Fengwei Zhang, Shiyong Lu, and Weidong Shi. 2018. A comparison
     and Networks (DSN). IEEE, Taipei, Taiwan, 438–450. https://doi.org/10.1109/               study of intel SGX and AMD memory encryption technology. In Proceedings of
     DSN48987.2021.00054                                                                       the 7th International Workshop on Hardware and Architectural Support for Security
[11] Javier GonzÃ¡lez and Philippe Bonnet. 2013. Towards an Open Framework                     and Privacy (HASP ’18). Association for Computing Machinery, New York, NY,
     Leveraging a Trusted Execution Environment. In Cyberspace Safety and Security             USA, 1–8. https://doi.org/10.1145/3214292.3214301
     (Lecture Notes in Computer Science), Guojun Wang, Indrakshi Ray, Dengguo Feng,       [29] Olga Ohrimenko, Felix Schuster, Cedric Fournet, Aastha Mehta, Sebastian
     and Muttukrishnan Rajarajan (Eds.). Springer International Publishing, Cham,              Nowozin, Kapil Vaswani, and Manuel Costa. 2016. Oblivious Multi-Party Machine
     458–467. https://doi.org/10.1007/978-3-319-03584-0_35                                     Learning on Trusted Processors. In 25th USENIX Security Symposium (USENIX
[12] Shay Gueron. 2016. A Memory Encryption Engine Suitable for General Purpose                Security 16). USENIX Association, Austin, TX, 619–636. https://www.usenix.
     Processors. Technical Report 204. Intel. http://eprint.iacr.org/2016/204                  org/conference/usenixsecurity16/technical-sessions/presentation/ohrimenko
[13] Danny Harnik, Eliad Tsfadia, Doron Chen, and Ronen Kat. 2018. Securing the           [30] Meni Orenbach, Pavel Lifshits, Marina Minkin, and Mark Silberstein. 2017. Eleos:
     Storage Data Path with SGX Enclaves. arXiv:1806.10883 [cs.CR] http://arxiv.               ExitLess OS Services for SGX Enclaves. In Proceedings of the Twelfth European
     org/abs/1806.10883 arXiv: 1806.10883.                                                     Conference on Computer Systems (EuroSys ’17). Association for Computing Ma-
[14] Intel. 2016.        Intel Protected File System Library.                    https:        chinery, New York, NY, USA, 238–253. https://doi.org/10.1145/3064176.3064219
     //www.intel.com/content/dam/develop/external/us/en/documents/                        [31] Christian Priebe, Kapil Vaswani, and Manuel Costa. 2018. EnclaveDB: A Secure
     overviewofintelprotectedfilesystemlibrary.pdf                                             Database Using SGX. In 2018 IEEE Symposium on Security and Privacy (SP). IEEE,
[15] Intel. 2021.     3rd Gen Intel Xeon Scalable Processors Brief.              https:        San Francisco, CA, 264–278. https://doi.org/10.1109/SP.2018.00025
     //www.intel.com/content/www/us/en/products/docs/processors/xeon/3rd-gen-             [32] Felix Schuster, Manuel Costa, CÃ©dric Fournet, Christos Gkantsidis, Marcus
     xeon-scalable-processors-brief.html                                                       Peinado, Gloria Mainar-Ruiz, and Mark Russinovich. 2015. VC3: Trustworthy
[16] Intel. 2021.      Intel Software Guard Extensions SDK Developer Refer-                    Data Analytics in the Cloud Using SGX. In Proceedings of the 2015 IEEE Symposium
     ence.      https://download.01.org/intel-sgx/sgx-linux/2.15.1/docs/Intel_SGX_             on Security and Privacy (SP ’15). IEEE Computer Society, USA, 38–54. https:
     Developer_Reference_Linux_2.15.1_Open_Source.pdf                                          //doi.org/10.1109/SP.2015.10
[17] Simon Johnson, Raghunandan Makaram, Amy Santoni, and Vin-                            [33] Yuanyuan Sun, Sheng Wang, Huorong Li, and Feifei Li. 2021. Building enclave-
     nie Scarlata. 2021.        Supporting intel sgx on multi-socket platforms.                native storage engines for practical encrypted databases. Proceedings of the
     https://www.intel.com/content/dam/www/public/us/en/documents/white-                       VLDB Endowment 14, 6 (Feb. 2021), 1019–1032. https://doi.org/10.14778/3447689.
     papers/supporting-intel-sgx-on-mulit-socket-platforms.pdf                                 3447705
[18] David Kaplan, Jeremy Powell, and Tom Woller. 2016. AMD memory encryption.            [34] Kuniyasu Suzaki, Kenta Nakajima, Tsukasa Oi, and Akira Tsukamoto. 2021. TS-
     AMD. http://developer.amd.com/wordpress/media/2013/12/AMD_Memory_                         Perf: General Performance Measurement of Trusted Execution Environment
     Encryption_Whitepaper_v7-Public.pdf                                                       and Rich Execution Environment on Intel SGX, Arm TrustZone, and RISC-V
[19] Tim Kiefer, Benjamin Schlegel, and Wolfgang Lehner. 2013. Experimental evalu-             Keystone. IEEE Access 9 (2021), 133520–133530. https://doi.org/10.1109/ACCESS.
     ation of NUMA effects on database management systems. In Datenbanksysteme                 2021.3112202 Conference Name: IEEE Access.
     für Business, Technologie und Web (BTW) 2025, Volker Markl, Gunter Saake, Kai-       [35] Meysam Taassori, Ali Shafiee, and Rajeev Balasubramonian. 2018. VAULT: Reduc-
     Uwe Sattler, Gregor Hackenbroich, Bernhard Mitschang, Theo Härder, and Veit               ing Paging Overheads in SGX with Efficient Integrity Verification Structures. In
     Köppen (Eds.). Gesellschaft für Informatik e.V., Bonn, 185–204.                           Proceedings of the Twenty-Third International Conference on Architectural Support
[20] Taehoon Kim, Joongun Park, Jaewook Woo, Seungheun Jeon, and Jaehyuk Huh.                  for Programming Languages and Operating Systems. ACM, Williamsburg VA USA,
     2019. ShieldStore: Shielded In-memory Key-value Storage with SGX. In Pro-                 665–678. https://doi.org/10.1145/3173162.3177155
     ceedings of the Fourteenth EuroSys Conference 2019 (EuroSys ’19). Association        [36] Hongliang Tian, Qiong Zhang, Shoumeng Yan, Alex Rudnitsky, Liron Shacham,
     for Computing Machinery, New York, NY, USA, 1–15. https://doi.org/10.1145/                Ron Yariv, and Noam Milshten. 2018. Switchless Calls Made Practical in Intel
     3302424.3303951                                                                           SGX. In Proceedings of the 3rd Workshop on System Software for Trusted Execution
[21] Robert Krahn, Donald Dragoti, Franz Gregor, Do Le Quoc, Valerio Schiavoni,                (SysTEX ’18). Association for Computing Machinery, New York, NY, USA, 22–27.
     Pascal Felber, Clenimar Souza, Andrey Brito, and Christof Fetzer. 2020. TEEMon:           https://doi.org/10.1145/3268935.3268942
     A continuous performance monitoring framework for TEEs. In Proceedings of            [37] Sébastien Vaucher, Rafael Pires, Pascal Felber, Marcelo Pasin, Valerio Schiavoni,
     the 21st International Middleware Conference (Middleware ’20). Association for            and Christof Fetzer. 2018. SGX-Aware Container Orchestration for Heterogeneous
     Computing Machinery, New York, NY, USA, 178–192. https://doi.org/10.1145/                 Clusters. In 2018 IEEE 38th International Conference on Distributed Computing
     3423211.3425677                                                                           Systems (ICDCS). IEEE, Vienna, Austria, 730–741. https://doi.org/10.1109/ICDCS.
[22] Ximing Liu, Wenwen Wang, Lizhi Wang, Xiaoli Gong, Ziyi Zhao, and Pen-Chung                2018.00076
     Yew. 2020. Regaining Lost Seconds: Efficient Page Preloading for SGX Enclaves.       [38] Srinivas Devadas Victor Costan. 2016. Intel SGX Explained. Technical Report 086.
     In Proceedings of the 21st International Middleware Conference (Middleware ’20).          MIT. http://eprint.iacr.org/2016/086
     Association for Computing Machinery, New York, NY, USA, 326–340. https:              [39] Dhinakaran Vinayagamurthy, Alexey Gribov, and Sergey Gorbunov. 2019.
     //doi.org/10.1145/3423211.3425673                                                         StealthDB: a Scalable Encrypted Database with Full SQL Query Support. Pro-
[23] Mohammad Mahhouk, Nico Weichbrodt, and RÃ¼diger Kapitza. 2021. SGXoMe-                    ceedings on Privacy Enhancing Technologies 2019, 3 (July 2019), 370–388. https:
     ter: Open and Modular Benchmarking for Intel SGX. In Proceedings of the 14th              //doi.org/10.2478/popets-2019-0052 Publisher: Sciendo Section: Proceedings on
     European Workshop on Systems Security (EuroSec ’21). Association for Computing            Privacy Enhancing Technologies.
     Machinery, New York, NY, USA, 55–61. https://doi.org/10.1145/3447852.3458722         [40] Nico Weichbrodt, Pierre-Louis Aublin, and RÃ¼diger Kapitza. 2018. sgx-perf: A
[24] Kajetan Maliszewski, Jorge-Arnulfo QuianÃ©-Ruiz, Jonas Traub, and Volker                  Performance Analysis Tool for Intel SGX Enclaves. In Proceedings of the 19th Inter-
     Markl. 2021. What is the price for joining securely?: benchmarking equi-joins in          national Middleware Conference (Middleware ’18). Association for Computing Ma-
     trusted execution environments. Proceedings of the VLDB Endowment 15, 3 (Nov.             chinery, New York, NY, USA, 201–213. https://doi.org/10.1145/3274808.3274824
     2021), 659–672. https://doi.org/10.14778/3494124.3494146                             [41] Ofir Weisse, Valeria Bertacco, and Todd Austin. 2017. Regaining Lost Cycles with
[25] Luther Martin. 2010. XTS: A Mode of AES for Encrypting Hard Disks. IEEE                   HotCalls: A Fast Interface for SGX Secure Enclaves. In Proceedings of the 44th
     Security Privacy 8, 3 (2010), 68–69. https://doi.org/10.1109/MSP.2010.111                 Annual International Symposium on Computer Architecture (ISCA ’17). Association
[26] Frank McKeen, Ilya Alexandrovich, Ittai Anati, Dror Caspi, Simon Johnson,                 for Computing Machinery, New York, NY, USA, 81–93. https://doi.org/10.1145/
     Rebekah Leslie-Hurd, and Carlos Rozas. 2016. Intel Software Guard Extensions              3079856.3080208
     (Intel SGX) Support for Dynamic Memory Management Inside an Enclave. In              [42] Bin Cedric Xing, Mark Shanahan, and Rebekah Leslie-Hurd. 2016. IntelÂ®
     Proceedings of the Hardware and Architectural Support for Security and Privacy            Software Guard Extensions (Intel SGX) Software Support for Dynamic Memory
     2016 (HASP 2016). Association for Computing Machinery, New York, NY, USA,                 Allocation inside an Enclave. In Proceedings of the Hardware and Architectural
     1–9. https://doi.org/10.1145/2948618.2954331                                              Support for Security and Privacy 2016 on - HASP 2016. ACM Press, Seoul, Republic
[27] Frank McKeen, Ilya Alexandrovich, Alex Berenzon, Carlos V. Rozas, Hisham Shafi,           of Korea, 1–9. https://doi.org/10.1145/2948618.2954330
     Vedvyas Shanbhogue, and Uday R. Savagaonkar. 2013. Innovative instructions           [43] C. Zhao, D. Saifuding, H. Tian, Y. Zhang, and C. Xing. 2016. On the Performance
     and software model for isolated execution. In Proceedings of the 2nd International        of Intel SGX. In 2016 13th Web Information Systems and Applications Conference
     Workshop on Hardware and Architectural Support for Security and Privacy - HASP            (WISA). IEEE, Wuhan, China, 184–187. https://doi.org/10.1109/WISA.2016.45
     ’13. ACM Press, Tel-Aviv, Israel, 1–1. https://doi.org/10.1145/2487726.2488368       [44] Jinwei Zhu, Kun Cheng, Jiayang Liu, and Liang Guo. 2021. Full encryption: an end
                                                                                               to end encryption mechanism in GaussDB. Proceedings of the VLDB Endowment
                                                                                               14, 12 (July 2021), 2811–2814. https://doi.org/10.14778/3476311.3476351
