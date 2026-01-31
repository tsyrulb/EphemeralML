                                         Confidential LLM Inference: Performance and Cost
                                                    Across CPU and GPU TEEs
                                                      Marcin Chrapek                     Marcin Copik                Etienne Mettaz                 Torsten Hoefler
                                                         ETH Zurich                       ETH Zurich                   ETH Zurich                     ETH Zurich
                                                    Zurich, Switzerland               Zurich, Switzerland          Zurich, Switzerland            Zurich, Switzerland
                                                 marcin.chrapek@inf.ethz.ch



                                            Abstract—Large Language Models (LLMs) are increasingly
                                         deployed on converged Cloud and High-Performance Com-
arXiv:2509.18886v1 [cs.PF] 23 Sep 2025




                                         puting (HPC) infrastructure. However, as LLMs handle con-
                                         fidential inputs and are fine-tuned on costly, proprietary
                                         datasets, their heightened security requirements slow adoption
                                         in privacy-sensitive sectors such as healthcare and finance. We
                                         investigate methods to address this gap and propose Trusted
                                         Execution Environments (TEEs) as a solution for securing
                                         end-to-end LLM inference. We validate their practicality
                                         by evaluating these compute-intensive workloads entirely
                                         within CPU and GPU TEEs. On the CPU side, we conduct
                                         an in-depth study running full Llama2 inference pipelines
                                         (7B, 13B, 70B) inside Intel’s TDX and SGX, accelerated by
                                         Advanced Matrix Extensions (AMX). We derive 12 insights,
                                         including that across various data types, batch sizes, and
                                         input lengths, CPU TEEs impose under 10% throughput and
                                         20% latency overheads, further reduced by AMX. We run
                                         LLM inference on NVIDIA H100 Confidential Compute GPUs,
                                         contextualizing our CPU findings and observing throughput
                                         penalties of 4–8% that diminish as batch and input sizes grow.
                                         By comparing performance, cost, and security trade-offs, we        Fig. 1. Example attacks on LLMs that TEEs protect against and our
                                         show how CPU TEEs can be more cost-effective or secure             performance results for Llama2 7B inference in two CPU TEEs: a Virtual
                                                                                                            Machine (VM, TDX) and an application-based (App, SGX) one, and a GPU
                                         than their GPU counterparts. To our knowledge, our work
                                                                                                            TEE (cGPU).
                                         is the first to comprehensively demonstrate the performance
                                         and practicality of modern TEEs across both CPUs and GPUs
                                         for enabling confidential LLMs (cLLMs).                         administrators, and other tenants can carry out to leak
                                            Index Terms—Confidential LLMs; Trusted Execution Envi-       model information and influence inference results. Data
                                         ronments; Benchmarking; Inference; Performance Study            confidentiality and intellectual property (IP) theft pose critical
                                                                                                         threats to LLMs, for which the cost of engineering and
                                                                I. Introduction                          obtaining datasets is substantial. With training and fine-
                                            Large Language Models (LLMs) dominate the machine tuning alone amounting to tens of millions of dollars [73],
                                         learning (ML) landscape [18], [91]. Exemplified by model any security breach involving LLMs is increasingly costly
                                         families such as GPT [20], [64] and Llama [5], [41], [78], for CSPs, model providers (e.g., MetaAI, OpenAI, financial or
                                         [79], they have become prevalent in industry and everyday healthcare institutions), and end users.
                                         life across a growing number of domains. LLMs achieve              While such threats might seem distant, they led to
                                         human-like capabilities on multimodal data [85] and have        companies      banning internal LLM use [8] and are tangible.
                                         been applied to disciplines relying on confidential user        For  example,    health records processed by a cloud-deployed
                                         information, including healthcare [71], finance [86], sentiment LLM    for   insurance   could be stolen and used maliciously.
                                         analysis [16], legal cases [29], and document translation [47]. Even   if  leveraged  solely for illicitly training another model,
                                         Simultaneously, the ever-increasing size of LLMs has led        such   a  model  might   then  be probed through public queries,
                                         to changes in their deployment strategies. LLMs ranging         reconstructing     sensitive  data,  including names, addresses,
                                         from billions to trillions of parameters necessitate state-of-  Social   Security  numbers,  and  full  medical histories [22], [66].
                                         the-art hardware to meet their performance demands, which       We   also   observe reports  of backlash    against leveraging user
                                         is frequently provided by cloud service providers (CSPs).       data  for  AI features [63] as more   companies   offer personalized
                                            However, deploying within the cloud carries security         AI  (e.g.,  Meta’s AI  Studio  or Adobe    Creative).
                                         risks for LLMs that operate on expensive and confidential          The security community has addressed the issues of ML
                                         data. Figure 1 shows attacks that cloud providers, cluster IP theft and data confidentiality by employing three primary
approaches: model modifications (e.g., watermarking and             4) Open-sourcing our configuration1 and drawing 12 in-
user authentication [33], [46], [88]), cryptographic methods             sights from empirical results, guiding efficient deploy-
(e.g., homomorphic encryption [36]), and trusted execution               ment and TEE system design.
environments [57]. We conduct an analysis of these techniques             II. Protection Mechanisms for LLM Inference
in Section II and show that TEEs currently provide the
only viable method for protecting LLM inference. TEEs                Three approaches can be used to protect LLM inference:
offer a practical balance between robust security properties,     machine      learning (ML) methods, cryptographic methods such
performance costs, and generalizability.                          as Homomorphic         Encryption (HE) and multiparty computation
   Our work focuses on quantifying usability and perfor-          (MPC),     and  Confidential    Computing (CC) [59].
mance overheads of TEEs for protecting LLM inference                 ML      methods:     As  noted     in literature [88], current ML
by evaluating representative implementations of both CPU          methods      focus  on  post hoc    detection   of intellectual property
and GPU TEEs. In Section III, we start by evaluating the          (IP)   theft   in  the  form   of   model     verification  and passive
CPU side and conducting an in-depth study of Intel’s Trust        protections,     falling short   in  actively  covering   against model
Domain Extensions (TDX) and Software Guard Extensions             or  data    theft. Example    approaches      include  using  signatures
(SGX), representing common approaches to implementing embedded in the model with model theft verification using
TEEs: through virtual machines (VMs) and processes. We input/output pairs [49], passport [37] or backdoor [87]
identify the best-performing frameworks and present the authentication, and watermarks in model output or weights
TEE performance overheads for throughput and latency in used for ownership verification [19], [76].
                                                                     While these protect against specific attacks, they do not
an end-to-end Llama2 (7B, 13B, and 70B) inference pipeline
                                                                  provide exhaustive and measurable security properties. The
across various batch sizes, input lengths, and data types.
                                                                  cost of losing confidentiality or IP theft makes it challenging
Leveraging this compute-intensive workload, we derive 12
                                                                  to rely only on them. Additionally, ML methods frequently
key insights on the performance of confidential LLM (cLLM)
                                                                  require expensive retraining, alter the model’s accuracy,
hosting, with practical guidelines for users and cloud providers.
                                                                  fail to secure the confidentiality of user prompts [88], and
Our insights can be generalized to other TEE deployments and
                                                                  cannot be combined together [75]. Cryptographic approaches,
LLM systems. For example, we demonstrate how Advanced
                                                                  such as HE and MPC, address these issues through strong
Matrix Extensions (AMX) directly result in lower overheads
                                                                  cryptographic protocols.
for TEEs. Figure 1 displays our example performance results,
                                                                     Cryptographic methods: HE allows conducting math-
showing that TEEs for LLMs incur only 4-7% throughput
                                                                  ematical and logical operations on encrypted data without
reduction compared to overheads of up to 100s of percent for
                                                                  decrypting [13]. HE has been explored in the context of
other applications [14], [27], [55].
                                                                  DNNs [33], [51], [84]. However, except for a few structured
   In Section V-D, we present GPU results evaluated on
                                                                  examples [21], [24], the state-of-the-art HE is not practical.
NVIDIA’s H100s that put our CPU results in perspective. We
                                                                  HE operations on encrypted data can have up to 10,000x
compare these two setups, considering cost, performance, and
                                                                  performance and size overheads, taking minutes to conduct
security. For example, we show that with AMX, CPU-based
                                                                  simple MNIST [33] or RESNET [36] inference, and making
TEEs can be more cost-efficient than confidential NVIDIA
                                                                  LLM inference intangible. HE approaches also do not provide
H100 GPUs. Finally, in Section VI, we evaluate one of the most
                                                                  integrity protection. MPC is close to HE and has similar
common LLM extensions: Retrieval Augmented Generation
                                                                  practicality issues, but involves multiple parties [82].
(RAG) [39]. We run full RAG pipelines, including Elasticsearch
                                                                     Confidential Computing: CC offers an alternative in
databases, in TEEs, and report their 7% overheads. We
                                                                  the form of TEEs, using security primitives implemented in
demonstrate how our lessons on CPU and GPU TEEs directly
                                                                  hardened hardware. Compared to HE and MPC, which rely on
extend to these types of deployments. To our knowledge,
                                                                  obscuring data and functions, TEEs offer a secure and isolated
our research is the first to comprehensively demonstrate
                                                                  environment, frequently referred to as an enclave. Users can
the performance and practicality of modern TEEs across
                                                                  verify enclaves in a safe, hardware-enabled process called
both CPUs and GPUs for enabling cLLMs. Our work can
                                                                  attestation. TEEs ensure the confidentiality and integrity of
be replicated and evaluated seamlessly on other systems with
                                                                  running programs and their data, protecting against external
the open-source implementation and configuration we release.
                                                                  and privileged attackers, such as system administrators. TEEs
In summary, our contributions are:
                                                                  achieve this by prohibiting access to or modification of the
  1) Demonstrating how TEEs currently offer the only prag-
                                                                  memory contents of running programs [70], including sensi-
      matic solution for protecting LLM inference.
                                                                  tive data like weights or user-confidential information.TEEs
  2) Characterizing performance of CPU TEEs (SGX, TDX) on
                                                                  widely available on CSP platforms include CPU-based exam-
      Llama2 (7B/13B/70B), showing overheads of less than 10%
                                                                  ples such as AMD’s Secure Encrypted Virtualization-Secure
      for throughput and 20% for latency, identifying sources
                                                                  Nested Paging (SEV-SNP) [45], Intel’s SGX [28], [42], [54] and
      of performance degradation and optimal configurations.
                                                                  TDX [23], ARM’s TrustZone [67] and CCA [53], and GPU-
  3) Demonstrating how these relate to GPU TEEs by com-
                                                                  based examples such as NVIDIA’s Confidential GPUs [62].
      paring with CPU TEEs in terms of cost-effectiveness,
      performance, and security.                                    1 github.com/spcl/confidential-llms-in-tees
  Although TEEs do not provide the formal guarantees of
HE or MPC, they still offer quantifiable defenses, particularly
against integrity attacks that HE and MPC cannot address.
Unlike many ML approaches, TEE protection mechanisms
actively ensure enforcement of trust boundaries. However,
performance and programmability are often cited as the
two primary limitations of TEEs [14]. Because their security
primitives lie on the critical path, TEEs incur non-negligible
overhead. Nonetheless, as we show in our evaluation, TEE’s
overheads remain substantially lower than those imposed
by HE schemes. Similarly, although TEEs require some
security expertise, leveraging VM TEEs and frameworks like
Gramine [81] eliminates the need for application modifications
necessary for HE and ML methods.
   Insight 1: TEEs offer a practical balance between security,
performance, and programmability.

                        III. CPU TEEs
                                                                  Fig. 2. Our software stack with the layers we protect in Intel TDX and SGX,
   To investigate practical deployments, we limit ourselves to    and an extract from our Gramine manifest template file.
CPU TEEs offered by major CSPs. The options are limited
to AMD and Intel since other TEEs, such as ones based             cant code modifications. Unlike alternatives, it has lower re-
on RISC-V [50] or ARM [67], are not widely available. We          quirements on the format of protected applications [74], is not
selected Intel’s TEEs for two reasons. Firstly, they include      proprietary [17], and is mature [72]. Gramine automatically
support for AMX, an on-chip matrix operation hardware             applies integrity and confidentiality protections to storage,
accelerator that introduces CPU-native support for formats        simplifies attestation, and transparently uses instructions for
such as brain-floating-points (bfloat16) and 8-bit integers       leaving and entering the SGX enclave during system calls. To
(int8). AMX improves LLM performance 2-6x [61] (Figure 8),        increase performance, Gramine emulates some system calls
and we investigated whether these units also impact the           without exiting the SGX enclave. However, if a given call is
performance of TEEs (Section IV-C). Secondly, they provide        not implemented fully, it can result in considerable overhead.
us with two common ways of implementing TEEs (VMs                 As we experienced firsthand, this can create a challenge while
and processes) within the same system, covering other TEEs        working with SGX, especially with complex workloads.
and enabling an apples-to-apples comparison without scaling          Gramine exposes its features via a Manifest file, which
performance results. For example, AMD’s TEE stack relies on       outlines the enclave size, the number of threads, the binary to
similar security mechanisms to Intel’s TDX, resulting in close    be run, the files that can be trusted, and where to obtain the
benchmark overheads [55].                                         cryptographic decryption keys. Figure 2 shows an example
                                                                  excerpt from a Manifest file.
A. Process-based TEEs: SGX
   SGX programming model differentiates between SGX- B. VM-based TEEs: TDX
protected and unprotected program sections. The former,            TDX is a virtual machine (VM) based TEE that introduces
located within an enclave, is safeguarded by SGX capabilities, security features using a hardened hardware-enabled kernel
while the latter is unsecured. SGX has two sources of overhead. virtual machine (KVM) hypervisor. In the TDX security
First, data in the enclave is protected by memory encryption model, the entire VM is protected. This approach aligns well
and integrity checks. Second, operations switching to the SGX with the CSP virtualization trend and significantly simplifies
unprotected program sections (e.g., IO such as reading a file) development, eliminating the need for special functions when
save SGX state and invalidate the caches.                       entering or exiting the enclave. TDX also runs programs
   SGX enclaves are frequently deployed on top of library op- within a standard Linux OS, such as Ubuntu, allowing for the
erating systems (OSs) created for TEEs, such as Gramine [81] easy execution of complex distributed AI frameworks, such
or Occlum [74]. These are lightweight layers between the as DeepSpeed [15], which we use. However, this convenience
host system and applications, intercepting any system calls comes at the price of an increased attack surface. TDX requires
to ensure they are conducted securely. These address some trusting the entire VM OS and associated services, rather
inconveniences of the original SGX software development kit than just a minimal library OS, like in SGX. Using VMs
(SDK), which required users to manually rewrite applications also implies a virtualization performance tax, which can
with secure and insecure sections.                              reach SGX’s overheads as we demonstrate in Section III-D.
   In our study, we use the open-source Gramine [81] library Furthermore, some security aspects handled by frameworks,
OS that enables porting applications to SGX without signifi- such as Gramine, are not performed automatically in TDX.
           30                                                                  they are fundamentally based on the same computational
                                                                               patterns. In this sense, Llama2 also represents well other
           25
Time (s)
                                                                               dense transformer LLMs, such as GPT or OPT. This has been
           20                                                                  confirmed empirically by consistent performance patterns
           15                                                                  between these LLMs [61]. To verify that this is similar for
           10                                                                  TEEs, we also evaluated Llama3 8B, GPT-J 6B, Falcon 7B,
                                                                               Baichuan2 7B, and Qwen 7B, and found 3.1-13.1% overheads,
    E X ( bf16L)M (bf16p) (mixedH) F (bf16IP) EX (f32L) LM (f32) HF (f32)      in line with our Llama 7B results. We report user-perceived
  IP        vL ma.cp                                v                          performance: throughput (tokens per second) and latency
             Lla                                                               (time to receive next token). For latency, we measured the
 Fig. 3. Comparison of single-socket, bare metal wall CPU runtime on EMR1      generation time for each token and its inverse for throughput.
 of different backends and datatypes for Llama2 7B inference over 1024 input   We run multiple generations for each experiment, measuring
 and 128 output tokens with beam and batch sizes equal to 1. HF is Hugging
 Face, bf16 is bfloat16, f32 is float32.
                                                                               at least 1000 output tokens. We used two inference data
                                                                               types: bfloat16 and int8. For the latter, we quantized
 For example, users must protect the filesystem, e.g., by using                the models. We evaluate four hardware configurations: the
 Linux Unified Key Setup (LUKS) [38] full-disk encryption.                     baseline represents results from a bare-metal machine, SGX
   To use TDX, one must define a VM with a Quick Emulator                      from Gramine v1.7 running on SGX, VM from a raw VM
 (QEMU) command or a libvirt definition file. These specify                    without security features, and TDX from a TDX-enabled VM.
 hardware details, such as boot files, virtual-to-physical core
                                                                               D. Single socket
 mapping, and memory size, and result in a greater perfor-
 mance impact than enabling TDX (Section IV).                        We first establish baseline performance. Figure 4 shows
                                                                  the throughput (batch size = 6, beam size = 4) and the
      Insight 2: TDX is considerably easier to work with than     next token latency (batch size = 1, beam size = 1). The
  SGX, especially for complex workloads.                          overhead of Gramine-SGX is between 4.80-6.15% while for
                                                                  TDX it is between 5.51-10.68%. TDX adds overhead of 3.02-
 C. Experimental setup                                            7.01% over VM. The results for different data types show
    1) Hardware and software: We used two Emerald Rapid that int8 generally achieves similar throughput to bfloat16
 dual-socket Intel systems. First EMR1, a dual socket Intel but almost half the latency. While in SGX, the overheads
 Xeon® Gold 6530 ($2130 [3]), each with 32 cores, 16x32GiB for int8 are similar to those for bfloat16, TDX shows
 4800MHz DDR5 memory, Ubuntu 23.10, Python 3.10.12, considerable differences, where int8 results are better in
 PyTorch 2.2.0, transformers 4.35.2, Intel extension for PyTorch terms of throughput but worse in terms of latency. For
 (IPEX) 2.2.0, and oneCCL PyTorch bindings 2.2.0. Second throughput, lower memory movement due to the inference
 EMR2, a dual socket Intel Xeon® Platinum 8580 ($10710 [4]), state in int8 and the corresponding reduction in necessary
 each with 60 cores, 16x32GiB 4800MHz DDR5 memory, address translations from guest to host memory results in
 Ubuntu 24.04, Python 3.10.16, PyTorch 2.3.0, transformers lower overheads. For latency, memory access costs due to
 4.38.1, IPEX 2.3.100, and oneCCL PyTorch bindings 2.3.0.         address translations and TEE memory protections are more
    2) Microbenchmark to select framework: To determine the pronounced when it is lower. All systems have a latency
 best framework for inference on the CPU, we evaluated mul- considerably below the average human reading speed of 200
 tiple popular options and assessed their performance across ms/word (approximately 300 words per minute) [69], which
 various data types using an example Llama2 7B LLM. We forms a performance standard that LLMs should meet. As
 compared Hugging Face’s transformers [83] (float32, bfloat16), we plot per-token statistics, we noticed outliers for SGX and
 vLLM [48] (float32, bfloat16), IPEX, and Llama.cpp [12] (mixed TDX, which we excluded in the violin plots using a Z-score
 datatype). As Figure 3 shows, IPEX is considerably faster than > 3 (≈0.64% of samples). As visible in the later plots, these
 all other frameworks, with the second vLLM being 50% slower do not contribute to the discussion but create considerable
 and Hugging Face 100% slower. IPEX leverages AMX and its noise due to variability in memory encryption.
 native bfloat16 support to achieve the best performance. It
                                                                       Insight 4: TDX and SGX have overheads as low as
 also utilizes the oneAPI Collective Communications Library
                                                                   4-10% for cLLM inference, preserving acceptable service
 (oneCCL), which is fine-tuned for Intel’s processors, making it
                                                                   performance.
 a suitable choice for running across multiple NUMA domains.
                                                                     The performance of SGX lies between that of a VM and
      Insight 3: Leveraging IPEX, and its AMX and oneCCL
                                                                  TDX. In our deployment, SGX runs on bare metal, where
  backends can double CPU inference performance.
                                                                  the host OS has more privileges than a VM and exposes
    3) Experiment details: We selected Llama2 [79] as a repre- the hardware more directly. TDX, on the other hand, does
 sentative example of dense transformers. While subsequent not have direct access to specific hardware features and
 iterations of the Llama family [5], [41] introduce models of must access the underlying system through virtualization
 different sizes, larger context windows, or mixtures of experts, layers, such as guest address translations not present in SGX.
                                                                                                                   Single socket
                                                                7B bf16                              13B bf16                            7B int8                            13B int8
                                                                  4.84%              26                 5.23%                               4.92%                              6.15%
                                               45.0                                                                       42
Next token latency [ms] Througput [tokens/s]

                                                                  7.01%              25                 5.17%                                                                  3.02%
                                               42.5                                                                       40                                 24
                                                                                     24
                                               40.0                                                                       38
                                               37.5       3.23%                      23         2.80%                                                        22
                                                                                                                          36        1.82% 3.76%                        3.44%
                                                              10.02%                 22             7.83%                                                                  6.36%
                                               35.0                                                                       34            5.51%
                                                                +5.58%                                +4.80%                             +5.43%              80              +5.19%
                                               70.0                                 130                                 45.0
                                                            +6.95%                                +6.56%                             +10.68%                             +9.37%
                                               67.5                                                                     42.5                                 75
                                                      +3.13%                        125     +2.25% +4.22%                       +5.38%                             +4.22%
                                               65.0                                                                     40.0
                                                                                    120                                                                      70
                                               62.5             +3.70%                                                  37.5             +5.02%                              +4.94%
                                                      l      VM        TDX   SGX            l      VM       TDX   SGX           l      VM      TDX   SGX           l      VM       TDX   SGX
                                      baremeta                                     baremeta                             baremeta                           baremeta
                 Fig. 4. TDX and SGX throughput and latency overheads stay within 4-10% for Llama2, and 1024 input, 128 output tokens on EMR1. A larger batch size
                 implies increased latency and throughput as less data movement is required per token. Inputs batched are computed on each layer, and a combined result is
                 forwarded to the next layer. Each layer has an increased latency over a single input but a decreased one over N separate inputs (increased throughput).

                                                                               Two sockets
                                                                                       performance by minimizing costly paging to regular memory,
                                                               70B bf16                             70B int8
                                                                                       which requires verification. Similarly, we observed higher
                        10                                                             performance without exposing the CPU core’s second logical
              Throughput




                                                           8
               [tokens/s]




                                                                                       thread (hyperthread) to TDX. In its default configuration,
                         8                                                             PyTorch only executes on the first logical thread of a core,
                                 7.03% 13.23%                     6.95% 1.52%
                                                           6                           with hyperthreads introducing noise. We also identified more
                         6           19.33%                           8.37%
                                                                                       concerning limitations with non-uniform memory access
                                   +61.81%                          +44.20%            (NUMA)    and huge pages.
latency [ms]
 Next token




                      600 +33.22% +21.46%               300 +25.68% +14.73%               1) Multiple sockets: Figure 6 shows inference performance
                                                                                       when deployed on two sockets. The performance overheads
                      400                                                              increase considerably, with TDX reporting an overhead of
                                                        200                            12.11-23.81%. There are two reasons for such performance.
                             VM B TDX VM NB                    VM B TDX VM NB First, the socket interconnect has a dedicated cryptographic
                                                                                       unit [44], and any data moving between sockets must be
                Fig. 5. The latency and throughput overheads of TDX over the VM backed
                with 2MB transparent huge pages (VM B) and VM backed with the same encrypted and integrity-protected, which incurs a performance
                huge pages but without any NUMA binding (VM NB) on EMR1.               penalty on the critical path.
                                                                                          Second, TDX and SGX drivers lack working NUMA support.
                The results quantify this virtualization tax by showing that Figure 5 shows the performance of TDX when running on
                running in a VM has an overhead of 1.82-5.38%. The cost of the 70B parameter model. This model is too large to fit into
                security is similar for SGX and TDX, as the overheads of SGX the memory of a single socket, and the 200ms service level
                over bare metal and TDX over VM are comparable.                        is no longer upheld. We compare TDX performance to a VM
                     Insight 5: Compared to SGX, TDX simplifies deployment             with  NUMA nodes bound in QEMU to the physical memory
                 but increases the trust boundary and pays a virtualization            of two  sockets (VM B) and non-bound (VM NB). While TDX
                 tax of 1-5%, making SGX more performant.                              is not as  low-performing as VM NB, it has a considerable
                                                                                       overhead compared to VM B, especially in terms of latency.
                                 IV. Tuning CPU TEE overheads                          We found that TDX’s KVM driver does not adhere to the
                   Our investigation revealed three key areas to achieving bindings that we provided.
                acceptable performance within TEEs: appropriate TEE config-               We are not displaying the results of SGX as its overheads
                uration, use of AMX, and optimizing memory efficiency.                 become prohibitively large, increasing up to 230%. While
                                                                                       encryption on the socket interconnect reduces performance,
                A. Configuring TEEs to avoid performance traps                         such performance in SGX is predominantly due to a lack
                   For SGX, we used the largest possible enclave page cache of proper support for NUMA. The memory is presented to
                (EPC), which significantly influences overheads. EPC is a the application as a single unified NUMA node, potentially
                secure, SGX-exclusive, limited-size memory area that acts as resulting in the allocation of all memory on a single socket.
                a cache for encrypted enclave code and data. EPC enhances While efforts have been made to optimize allocations to align
                                                                                                         Two sockets
                                                        7B bf16                        13B bf16                              7B int8                             13B int8
                                                      10.10%      5.59%     45       8.93%       5.37%                        4.70% 5.83%       40          8.59%     4.20%
                                                                                                                                                                2.43%
Next token latency [ms] Throughput [tok/s]

                                             70                                                               60
                                                                            40                                                                  35
                                             60                                                               50                                30
                                                                            35                                         5.94%
                                             50    6.46% 3.89%                    5.65% 3.49%                 40                                25       6.31%
                                                                                                                           10.36%
                                                         15.12%             30          13.82%                                 15.59%                             12.43%
                                                      +9.16%                         +7.33%                 32.5       +11.15%                             +12.46%
                                             50   +4.89% +4.07% +5.48%      80   +3.34% +3.86% +4.61%               +5.64% +5.22% +5.99%        55      +7.19% +4.92% +10.25%
                                                                                                            30.0
                                             45                             75                                                                  50
                                                                                                            27.5
                                             40                             70                              25.0                                45
                                             35         +15.15%             65         +12.27%              22.5             +17.81%            40               +23.99%
                       l                                            TDX           l                TDX              l                   TDX           l                     TDX
               baremeta VM FH VM TH                                       baremeta VM FH VM TH              baremeta VM FH VM TH              baremeta VM FH VM TH

Fig. 6. The throughput and latency overheads for VM with full 1GB huge pages (VM FH), 2MB transparent huge pages (VM TH), and TDX on EMR1. The
overheads of TDX over VM TH remain at 4-10%.

with the thread using the data [44], we have not found
                                                                                                                                                     baremetal

                                                                                                                                            Decoder Block [us]
                                                                                                                       800
                                                                                                                                            Total Duration Per
satisfactory performance of SGX in multiple sockets.
                                                                                                                                                     TDX




                                                                                                                                                     6.88%
   We also found that sub-NUMA clustering has a significant                                                            600




                                                                                                                                                  9.94%
influence on both SGX and TDX. Sub-NUMA clustering




                                                                                                                                                4.93%
                                                                                                                                                6.14%
                                                                                                                       400


                                                                                                                                             53.94%




                                                                                                                                            10.62%
(SNC) [60] in Intel CPUs divides a single socket into multiple
NUMA domains, aiming at improving performance for ML                                                                   200
workloads. TEE drivers also do not support sub-NUMA                                                                      0
domains, resulting in inefficient memory placement. In our
                                                                                                                      EX h PU tn

                                                                                                                      EX tio PU d




                                                                                                                                      PU d
                                                                                                                      EX ml lCPUmul
                                                                                                                                     CP orm




                                                                                                                     lin li mCP orm
                                                                                                                  (IP tten AddCar ad




                                                                                                                                    dC ad
                                                                                                                   (IP m tionClf at




                                                                                                                         lin p l )
                                                                                                                                       U)




                                                                                                                         RM n l )




                                                                                                                                         )
                                                                                                              po line a l )




                                                                                                                        ea ne U)
test runs, using sub-NUMA domains increased overhead by
                                                                                                                                 orm rn




                                                                                                                                 or rn




                                                                                                                                rAd ar
                                                                                                                                    u u
                                                                                                                               luM sil
                                                                                                                              en se
                                                                                                                             SN aye




                                                                                                                             SN aye
                                                                                                                     a ar ne




                                                                                                                            ea ine
                                                                                                                           rSi ar
more than eight times, from approximately 5% to 42%. As a                                                                         i
                                                                                                                         RM t l
                                                                                                                      EX pu




result, we disabled sub-NUMA clustering.
                                                                                                                          Att
                                                                                                                  (IP in


                                                                                                                       EX
                                                                                                                   (IP




                                                                                                                   (IP
                                                                                                                 EX
                                                                                                                  st

              Insight 6: TDX and SGX do not properly support
         NUMA bindings, which leads to a considerably degraded                                                (IP
         performance, especially in the case of models that do not                                           Fig. 7. The duration and TDX overhead of each decoder block layer for
                                                                                                             Llama7B on a single socket of EMR2.
         fit in the memory of a single socket.
  2) Hugepages: For TDX, we also identified that it does                                                     B. Per-block overheads
not use 1GB huge pages [65], which increases the number
                                                                                                                To better understand the sources of overhead, we traced
of necessary translation lookaside buffer (TLB) accesses,
                                                                                                             the single-socket inference of 128 in/out tokens for a batch
worsening memory access latency. Figure 6 also shows the
                                                                                                             size of 4 for TDX. We then parsed the traces to measure
performance of different VM hugepage allocation strategies.
                                                                                                             the time of each inference layer. We observed that decoder
VM FH uses preallocated 1GB hugepages, and VM TH uses
                                                                                                             blocks take 99.9% of the time, with the remainder devoted
2MB transparent hugepages. TDX overheads over VM TH
                                                                                                             to embedding and final normalization. Figure 7 shows the
remain the same order of magnitude as in the single socket
                                                                                                             duration and overheads for each decoder block layer. The most
case. We found that TDX in the background uses transparent
                                                                                                             significant overheads are incurred in input and post-attention
huge pages even if 1GB pages are provided. A larger data
                                                                                                             layer norms. However, these have large relative noises and
movement in the case of two NUMA nodes implies greater
                                                                                                             form only 3% of the total block time. The most considerable
TLB pressure, manifesting in larger overheads of VM TH
                                                                                                             cost in raw performance is incurred in self-attention and linear
and TDX compared to VM FH and bare metal, for which
                                                                                                             SiLU multiplication. Given that these have a considerable data
huge pages matter less. The overhead of VM TH over VM
                                                                                                             movement [43], it is clear that memory encryption is a major
FH quantifies the performance cost due to the lack of 1 GB
                                                                                                             contributor to the overheads. The time these take is impacted
hugepage support in TDX at 3.19–5.20%.
                                                                                                             by the arithmetic intensity, influenced by solutions such as
            Insight 7: TDX uses self-allocated transparent hugepages                                         AMX and operational parameters such as batch and input
         and ignores manually reserved hugepages, which costs up                                             sizes. These two parameters also considerably impact the exact
         to 5% of raw performance.                                                                           relative durations we have shown above. As we increased
                                                            bf16                                                                                                                   int8
               600                                                                                                 600




                                                                                -3.99%
Throughput
 (tokens/s)




                                                                                                        -65.83%
                                                                                                       -67.09%




                                                                                                                                                                                                -5.93%
                                                                                            -65.50%
               400                                                                                                 400




                                                                                           -68.02%
                                                                           -50.39%
                                                                           -51.78%
                                                                  -3.43%
                                                                -26.11%
                                                                -26.18%




                                                                                                      -3.04%




                                                                                                                                                                                                                                   -3.93%
                                                                                                                                                                                -4.43%




                                                                                                                                                                                                                                              -2.09%
                                                      -13.47%
                                                      -16.86%




                                                                                         -1.41%




                                                                                                                                                                                                                                            -85.38%
                                                                                                                                                                                                                                            -86.09%
                                                       -3.09%




                                                                                                                                                                 -4.27%




                                                                                                                                                                                                                      657.56% -91.93%
                                                                                                                                                                                                                       717.08% -92.17%
                                                                                                                                                                                                           -4.33%
                                                                                                                                                                                                         -91.72%
                                                                                                                                                                                                         -91.96%
                                            -3.24%




                                                                                                                                                                                         -92.01%
                                                                                                                                                                                         -92.61%
                                            -6.85%
                                            -9.09%




                                                                                                                                                -4.04%




                                                                                                                                                                           -94.86%
                                                                                                                                                                           -94.91%
                                                                                                                                                              -95.16%
                                                                                                                                                              -95.34%
                                                                                                                                              -95.54%
                                                                                                                                              -95.72%
                                                                                                                          1552.17% -95.71%
                                                                                                                           1734.91% -95.99%
                                -3.59%
                                -4.23%
                                -6.43%
               200




                                                                                                                                     -5.63%
                                                                                                                   200
                      -2.87%
                      -4.11%
                      -8.78%

                 0                                                                                                   0




                                                                                            193.94%
                               VM (AMX)                     VM (no AMX)




                                                                                           163.82%




                                                                                                                                                                              1236.14%
               0.3




                                                                                                                                                   1536.92%

                                                                                                                                                                1358.31%

                                                                                                                                                                             1087.38%
                                                                                                                                                                1274.01%
                                                                                                                                                  1390.11%




                                                                                                                                                                                            919.60%
                                                                                                                    0.6




                                                                                                                                                                                            882.62%


                                                                                                                                                                                                            672.06%
                               TDX (AMX)                    TDX (no AMX)




                                                                                                                                                                                                           618.39%
 Next token
 latency (s)




                                                                                                         6.81%
               0.2




                                                                                                                                                                                                                                              484.45%
                                                                                                       197.33%
                                                                              81.46%
                                                                             73.24%




                                                                                                      178.37%




                                                                                                                                                                                                                                             432.17%
                                                                                                                    0.4




                                                                                         8.60%
                                                                 33.54%
                                                                25.78%
                                                      22.31%
                                                      13.75%
                                            16.08%




                                                                           6.93%
                      10.87%




                                                                                                                                                                                                                                            6.72%
                                                                4.99%
                                                      5.74%




                                                                                                                                                                                                                      10.42%
                                            8.50%
                                            6.74%
                                8.99%
                                5.08%
                      9.10%


                                0.84%
                      1.13%




               0.1




                                                                                                                          12.58%
                                                                                                                    0.2




                                                                                                                                                                                                         8.65%
                                                                                                                                                                                         7.03%
                                                                                                                                                                           6.27%
                                                                                                                                                              7.46%
                                                                                                                                              6.20%
               0.0                                                                                                  0.0
                        1           2         4         8        16          32            64          128                     1                   2             4            8             16             32             64                 128
                                                                                                      Batch size
  Fig. 8. Comparison of performance between AMX and no-AMX systems as we scale the batch size for Llama2 7B, with 128 in and out tokens and beam size
  equal to one on EMR2. The overheads are relative to VM running AMX. We show the best performing setups: latency on two sockets, throughput on one.

  the batch and input sizes, we observed that self-attention                                                      As latency results are measured on two sockets, lower NUMA
  and linear SiLU remain the most significant contributors to                                                     traffic caused by AMX explains these benefits. Importantly, we
  overall block time, with self-attention dominating even more.                                                   also observed up to 96% of overhead in throughput and 1700%
                                                                                                                  in latency for int8. Such low performance occurs because
  C. Use of AMX                                                                                                   the model quantization is fine-tuned for AMX, and there is a
    As shown in Section III-C, using IPEX, which leverages                                                        lack of AVX implementation for int8 in IPEX.
  AMX, has a significant impact on inference performance.
                                                                                                                     Insight 8: AMX lowers TDX overheads, accelerates
  However, what we found is that AMX also minimizes TDX
                                                                                                                  workloads up to 2.6x, and enables quantized inference.
  overheads. For further experiments, we focus solely on TDX,
  which performs worse than SGX, forming a lower bound on
  performance. However, it is easier to work with, especially for                                                 D. Efficient use of memory
  experiments that disable AMX, limit the number of cores, or                                                       The final overheads we observed include memory protection
  run RAG pipelines. All VMs henceforth use 1GB hugepages.                                                        costs, which are influenced by the amount of paging and the
    Figure 8 investigates the benefits of AMX across batch sizes,                                                 application’s arithmetic intensity. We optimized the former by
  against a setup running IPEX without AMX. In the case of                                                        using TCMalloc [34], which reduces the memory pressure. For
  bfloat16, AMX initially provides a slight advantage of 1-4%,                                                    the latter, we used an OpenMP [30] version suitable for Intel
  which increases to hundreds of percent with larger batch sizes                                                  processors. However, the choice of operational parameters,
  (more compute). AMX not only significantly influences raw                                                       such as batch and input sizes, has a greater impact.
  performance but also reduces the overheads of TDX, lowering                                                       1) Batch size scaling: Figure 9 shows the results of varying
  them by up to 30% for latency and up to 2% for throughput.                                                      the batch size. As it is scaled, we expect more algorithmic
                                                            bf16                                                                                                                   int8
               750                                                                                                 600
                                                                                                                                  -13.21%
                               -5.68%
Throughput




                               -9.44%




                                                                                                                                   -7.74%
 (tokens/s)




                            -5.42%




                                                                                                                                -5.56%
                           -8.67%




               500
                                                                                                                                -9.75%
                           -1.35%




                                                                                                                               -3.96%
                           -4.08%




                                                                                                                               -3.47%




                                                                                                                               -6.67%
                                                                                                                              -7.27%




                                                                                                                   400
                                                                                                                              -0.97%
                          -4.36%




                                                                                                                               1.53%
                         -7.00%




                                                                                                                             -4.88%
                                                                                                                             -6.86%
                         -6.73%
                        -9.57%
                        -4.14%




                                                                                                                            -5.63%
                        -7.10%




                                                                                                                            -9.66%




                                                                                                                          -10.03%
                                                                                                                          -10.47%




                                                                                                                          -13.93%
                       -0.88%
                       -2.27%
                       -3.95%




                                                                                                                           -4.75%
                       -7.07%




                                                                                                                           -8.60%
                                                                                                                          -5.13%
                      -3.84%
                      -7.29%
                      -2.51%
                      -6.52%




               250                                                                                                 200
               4000                                                                                                  0
                               baremetal                 VM                TDX                                     400
latency (ms)
 Next token




                           11.15%




                                                                                                                               12.59%


                                                                                                                              15.74%
                         14.64%
                           4.06%




                                                                                                                               5.50%


                                                                                                                              6.64%
                         4.71%




                                                                                                                             18.09%




               200
                         9.40%
                       12.06%


                         0.73%
                       11.98%




                                                                                                                            13.93%
                       12.42%
                       12.62%
                       15.89%




                                                                                                                           13.09%
                        9.83%
                        2.71%




                                                                                                                           10.09%




                                                                                                                   200
                                                                                                                            6.95%
                                                                                                                          14.01%
                                                                                                                          12.68%
                                                                                                                          19.62%
                       6.73%
                       5.90%




                                                                                                                          16.19%
                      10.54%




                                                                                                                           4.86%
                       5.32%
                       7.17%
                       6.22%




                                                                                                                           5.67%
                                                                                                                          3.60%
                                                                                                                          6.10%
                                                                                                                          6.11%
                      2.95%




                                                                                                                          6.26%




                                                                                                                          7.08%




                 0                                                                                                   0
                       1        2       4         8     16       32        64 128 256 512                                    1                2           4           8       16          32             64 128 256 512
                                                                                                      Batch size
  Fig. 9. Comparison of next token latency and throughput as we scale the batch size with 128 in and out tokens and beam size of one on EMR2. Performance
  overheads are shown relative to bare metal. Latency is measured on two sockets, while throughput is measured on a single socket. Throughput for two
  sockets equals twice the shown values.
       intensity, which lowers TDX’s overhead stemming from                                   and data transfers over PCIe between CPU and GPU are
       memory encryptions. This is precisely what we observe. For                             encrypted and authenticated via a bounce buffer. This prevents
       int8, the workload saturates the throughput at batch size 64                           hypervisor or physical attackers from accessing sensitive
       when the overheads drop from 9-11% to 6% or less. bfloat16                             information. These transfers, together with an additional
       also achieves throughput saturation, but around a batch size                           kernel invocation latency, are the main costs of the current
       of 512. This is also when the overheads drop from 7-10% to                             cGPUs. To avoid the PCIe overhead, solutions such as PCIe
       4-7%. From a latency perspective, we do not observe such a                             IDE need to be used [2]. While PCIe transfers are protected,
       strong correlation, which is due to the overhead of socket                             the HBM memory of H100s is not. Additionally, the NVLINK
       interconnect data movement that also increases alongside                               communication is unprotected when combining multiple
       algorithmic intensity. A batch size of 64 achieves the best                            H100s, requiring secure communication through the host. The
       performance for bfloat16 throughput, when the overheads                                B100s resolve the main security issues of H100s and introduce
       drop to 2%. As this marks the inflection point for bare metal                          HBM memory and NVLINK encryption. While B100s address
       performance, we evaluate it across different input sizes.                              these issues, their availability in CC configurations makes it
          2) Input size scaling: Figure 10 shows the throughput                               challenging to evaluate the costs of these protections.
       performance against the input size. We observe that the
       overhead of TDX decreases as the input size increases, both                            B. Experimental setup
       for int8 and bfloat16, until it reaches 2048 tokens. The                                 We used an H100 NVL GPU with 94 GB of
       overhead variability stems from the interplay of caches and                            memory (~$30,000 [6]) rented from Azure (confidential
       AMX. As we initially increase the input size, we benefit from                          NCCads_H100_v5 and non-confidential NCads_H100_v5), with
       the workload saturating the AMX units and becoming more                                a 40-virtual CPU (vCPU) AMD EPYC 9V84 host and 320 GiB
       compute-bound, similarly to the batching case. However, as                             memory. We deployed Ubuntu 24.04 and leveraged vLLM [48]
       we increase the input size, the KV cache size per new token                            version 0.8.5 as an optimized inference framework. As our
       also grows. Eventually, it reaches the point where each token                          machine is rented, we do not have access to bare metal and
       causes a considerable cache miss rate, making the workload                             present the results for raw and Confidential GPUs (cGPU).
       memory-bound. We observe increased overheads for both
       TDX and VM, as this also leads to TLB misses. At this regime,                          C. Batch and input size scaling
       we achieve overheads similar to smaller batch sizes.
                                                                                                  Figure 11 shows the performance of GPUs for Llama2 7B for
               Insight 9: TDX has the lowest overhead when the
                                                                                              different batch sizes and input lengths. cGPUs exhibit similar
            workload is compute-bound.
                                                                                              performance to CPU TEEs, albeit with lower noise. This is
                              V. GPU TEEs                                                     an expected behavior since GPUs do not have encrypted
                                                                                              memory on the critical path. As both batch size and input
         To put our CPU results in perspective, we also investigate
                                                                                              length increase, the cGPU performance improves, primarily
       cGPUs. At the time of writing, the GPU-based TEE introduced
                                                                                              due to increased arithmetic intensity. Since the share of time
       by NVIDIA in the Hopper architecture is the only accelerated
                                                                                              spent on setup remains roughly the same (including overhead-
       TEE solution entering the space on a large scale. H100s
                                                                                              inducing kernel invocations and data transfers from the CPU),
       with CC enabled are available only in production mode at
                                                                                              the overheads naturally decrease. While for inference, the
       Azure [1] and GCP [7]. Their successors, B100s, are currently
                                                                                              data transfer is minimal, for workloads such as LLM training,
       not available in any CSP in the CC configuration.
                                                                                              it is large. Solutions such as TDX Connect [23] and SEV IO [9]
        A. NVIDIA Confidential GPUs                                                           are in development to address these overheads.
           cGPUs require a host CPU TEE, enabling GPU attestation.                              Insight 10: GPU TEEs achieve less than 10% overheads,
        Users can run their kernels on cGPUs without any changes                              which decreases with larger batch and input sizes.
        to existing CUDA applications. All command buffers, kernels,
                                                          bf16                                                                     int8
Throughput (tokens/s)




                        600                          baremetal           VM          TDX      800
                                                                                              600
                                                                            -2.29%




                        400
                               -2.13%




                                                                            0.46%




                                                                                                      -4.78%
                              -6.75%




                                                                                                     -8.82%
                                        -2.88%




                                                                                                                -3.71%




                                                                                                                                                    -1.60%
                                                                                                                                                    -2.41%
                                        -5.88%




                                                                                                               -8.71%
                                                 -0.73%




                                                                                                                          -1.41%
                                                 -4.42%




                                                                                                                                                             -10.18%




                                                                                              400
                                                                                     -5.03%




                                                                                                                         -6.99%
                                                                                     -9.30%
                                                          -2.32%




                                                                                                                                                             -5.63%
                                                           1.49%




                                                                                                                                   -2.08%
                                                                                                                                    2.83%
                                                                   -2.06%
                                                                    0.52%




                        200
                                                                                                                                            5.13%
                                                                                                                                            1.37%




                                                                                              200
                          0                                                                     0
                               32        64      128      256      512      1024     2048             32        64       128       256      512     1024     2048
                                                                                Input size (tokens)
        Fig. 10. Comparison of generation throughput as we scale the input size for Llama2 7B on a single socket, with 128 out tokens, beam size 1, batch size 64,
        on EMR2. The overheads are relative to bare metal.
                                                                                  input length=128                                                                                                                                 batch size=4
                                                                                                                                                                             600
  Throughput (tokens/sec)
                            6000                       GPU
                                                       cGPU
                            4000                                                                                                                                             400




                                                                                                                                                              -4.36%
                                                                                                                                                 -5.59%




                                                                                                                                                                                               -6.83%
                                                                                              -7.02%




                                                                                                                                                                                                                          -6.48%
                                                                                                                                   -4.87%




                                                                                                                                                                                                                                                   -6.53%


                                                                                                                                                                                                                                                                              -5.55%
                                                                                                                      -4.91%
                                                                                  -7.12%




                                                                                                                                                                                                                                                                                                         -5.15%
                            2000                                                                                                                                             200

                                                                    -6.83%




                                                                                                           -4.71%
                                                       -7.89%
                                         -7.45%



                                 0                                                                                                                                             0
                                          1             2            4             8          16 32 64 128 256 512                                                                          128                        256         512        1024                                                2048
                                                                                             Batch size                                                                                                                   Input length (tokens)

               Fig. 11. GPU throughput as a function of batch and input sizes. As both increase, the overheads are minimized, and oscillate between 7.5% and 4.4%

   D. Comparing CPUs and GPUs                                                                                                                                               and the amount of memory separately, we assumed 128 GB
                                                                                                                                                                            of memory, which we found to be sufficient for deploying
      1) Hybrid setups: Results in Section V-C indicate that the                                                                                                            Llama2 7B in all the shown cases. We then scaled the number
   GPU has a much better raw performance. This occurs as                                                                                                                    of vCPUs, keeping the memory size constant. Memory initially
   long as the model can be entirely fitted on the GPU. Prior                                                                                                               dominates the cost of renting, as it is fixed regardless of the
   research has shown [61] that if parts of the model need                                                                                                                  number of CPU cores used. As we add cores, the performance
   to be offloaded to the host memory, the AMX-accelerated                                                                                                                  increases, lowering the price per million tokens, which starts
   CPUs outperform GPUs. This is even more so the case for                                                                                                                  climbing back to 32 cores when the throughput plateau is
   confidential computing, as any data movement between CPU                                                                                                                 reached. As we increase the batch size, the computational
   and GPU is more expensive, due to the cost of encrypting                                                                                                                 needs increase, making the larger machines more economical.
   the PCIe bounce buffer. We demonstrate that in the case                                                                                                                  For example, at a batch size of 128, 32 cores become optimal.
   of confidential computing, two additional scenarios arise in                                                                                                             As this workload becomes memory-bound easily, renting an
   which CPUs outperform current GPUs.                                                                                                                                      almost 2x cheaper Sapphire Rapid performing up to 40%
      2) Resource efficiency: Figure 12 shows the throughput                                                                                                                worse [35], provides an even more affordable alternative.
   across different batch sizes (columns) and numbers of CPU
   cores used during inference. The results indicate that the                                                                                                                  We marked the cGPU cost-effectiveness with an orange
   workload remains compute-bound until 32 cores, after which                                                                                                               line in Figure 12. While more performant, GPUs also have a
   it becomes memory-bound, suggesting minimal performance                                                                                                                  significantly higher price per hour, resulting in cGPUs being
   gain above this number of cores. Similarly to prior plots, a                                                                                                             up to 100% more expensive. We observe that as the batch size
   batch size of 64 has the lowest TDX overheads.                                                                                                                           increases, the advantage of CPU TEEs slowly fades, until it
      Additionally, Figure 12 shows the cost of inference of 1                                                                                                              reaches a batch size of 128, at which point they equalize. Such
   million tokens. To evaluate the cost of running different setups,                                                                                                        behavior is expected as GPUs become more efficient with
   we used spot prices offered by Google Cloud Platform (GCP)                                                                                                               larger batch sizes [68]. LLM queries with low computational
   for the same machine type deployed in the US East 1 region.                                                                                                              intensity are especially more cost-efficient when using TEEs.
   As GCP allows users to select the number of vCPU cores                                                                                                                   Currently, NVIDIA supports CC only on H100 and B100

                                                  baremetal                                  VM                       TDX                         confidential H100 (cGPU)
                                              batch size = 1bs                                                        batch size = 4bs                                                  batch size = 16bs                                                        batch size = 64bs
                                                                                                    60                                                                      200
                            15                                                                                                                                                                                                                    400
                                                       -8.45%
Throughput




                                                                                                                               -7.90%
 (tokens/s)




                                                                                                                                                                                                     -7.33%




                                                                                                    40
                                                                                                                                                                                                                                                                              -0.36%




                            10
                                                                                                                                                                                                                                                                                                         -4.86%
                                                                                                                                                          -6.53%
                                              -7.71%



                                                                         -6.30%




                                                                                                                                                 -5.40%




                                                                                                                                                                                                                                -7.03%




                                                                                                                                                                                                                                                                                                                  -2.87%
                                                                                                                      -7.18%
                                                                                  -7.92%




                                                                                                                                                                   -7.31%




                                                                                                                                                                                                                                         -7.71%
                                                                                           -8.44%




                                                                                                                                                                                                                       -4.85%




                                                                                                                                                                                                                                                                                                -3.21%



                                                                                                                                                                            100
                                                                                                                                                                                            -6.32%
                                                                -7.45%




                                                                                                                                        -7.30%




                                                                                                                                                                                                                                                  200
                                                                                                                                                                                                                                                                     -3.05%
                                                                                                                                                                                                              -7.18%
                                     -7.78%




                                                                                                             -6.48%




                                                                                                                                                                                   -4.24%




                                                                                                                                                                                                                                                                                       -1.93%
                                                                                                                                                                                                                                                            -0.98%




                             5                                                                      20
                             0                                                                         0                                                                      0                                                                     0
 ($/million tokens)




                            20                         TDX=100.32%                                     6                       TDX=86.04%                                     2                      TDX=61.75%                                                               TDX=27.87%
  Estimated cost




                                                                                                                                                                                                                                                  1.0
                                                                                                       4
                            10                                                                                                                                                1                                                                   0.5
                                                                                                       2
                             0                                                                         0                           0                     0.0
                                     2 4 8 16 32 48 60                                                        2 4 8 16 32 48 60        2 4 8 16 32 48 60     2 4 8 16 32 48 60
                                                                                                                           Number of vCPUs
   Fig. 12. vCPU scaling and cost of generating on EMR2. Generation throughput includes the first token latency, measured over 128 in and out tokens on a
   single socket for bfloat16. The throughput overheads are with respect to bare metal, and the cost of overheads of TDX with respect to GPU.
                                   baremetal                                  VM                 TDX                         confidential H100 (cGPU)
                                 input size = 256                                      60
                                                                                                      input size = 512                                                     input size = 1024                                                   input size = 2048
                60
                                                                                                                                                             40                                                                  30
Throughput




                                          -7.12%




                                                                                                               -6.49%
 (tokens/s)


                                                                                       40




                                                                                                                                                                                    -6.05%
                40




                                                                                                                                                                                                                                                        -4.71%
                                                                                                                                                                                                                                 20




                                                                                                                                                   -10.04%
                                                                     -5.67%




                                                                                                                                                                                                                                                                                            -6.19%
                                                                                                                                                                                                               -5.51%
                                                            -5.19%




                                                                                                                                          -7.21%
                                                                              -6.84%




                                                                                                                                                                                                                        -8.27%
                                                                                                                                 -3.72%




                                                                                                                                                                                                                                                                                   -5.66%
                                 -7.13%




                                                                                                                                                                                                      -4.28%
                                                                                                      -5.77%




                                                                                                                                                                                                                                                                          -2.90%
                                                                                                                                                                           -5.42%




                                                                                                                                                                                                                                               -3.29%
                                                   -5.56%
                                                                                                                                                             20




                                                                                                                        -5.62%




                                                                                                                                                                                             -6.41%
                        -5.26%




                                                                                             -4.47%
                                                                                       20




                                                                                                                                                                                                                                                                 -4.42%
                                                                                                                                                                  -2.48%




                                                                                                                                                                                                                                      -0.94%
                20                                                                                                                                                                                                               10
                   0                                                                     0                                                                    0                                                                   0
                                                                                       7.5                                                                   10                                                                  15
   ($/million tokens)




                   6                      TDX=-10.94%                                                          TDX=-58.76%                                                          TDX=-82.25%                                                         TDX=-92.51%
    Estimated cost




                   4                                                                   5.0                                                                                                                                       10
                                                                                                                                                              5
                   2                                                                   2.5                                                                                                                                        5
                   0                                                                   0.0                       0                      0
                        2 4 8 16 32 48 60                                                    2 4 8 16 32 48 60        2 4 8 16 32 48 60   2 4 8 16 32 48 60
                                                                                                          Number of vCPUs
  Fig. 13. vCPU scaling and cost of generating tokens on EMR2. Throughput includes the first token latency, measured over 128 out tokens, batch size 4, on a
  single socket for bfloat16. The throughput overheads are with respect to bare metal, and the cost of cGPU overheads with respect to TDX.

  systems, excluding MIG [52] and older or less powerful GPUs,                                                                                           scheme, such as IPsec, is required on top of both CPUs and
  such as the A100, which are used to optimize cost efficiency.                                                                                          GPUs, which also introduces an overhead of up to 90% [25].
     To verify that CPU TEEs eventually lose their advantage
                                                                                                                                                                Insight 11: For strictest security workloads, and relatively
  when compute requirements are sufficient, we also evaluate
                                                                                                                                                             small LLMs such as Llama2 7B, where H100 GPUs would
  performance with varying input sizes for a batch size of 4.
                                                                                                                                                             be unsaturated (e.g., small batch or input sizes), CPU TEEs
  As results in Figure 13 reveal, from the cost perspective, CPU
                                                                                                                                                             offer a pragmatic way to secure inference.
  TEEs are considerably more sensitive to input size than cGPUs.
  The first batch size for which CPU TEEs are uncompetitive                                                                                                                    VI. Moving to RAG
  is 128, losing the 100% resource advantage of batch size
                                                                                                                                                            RAG is a practical showcase of our insights. RAG is an
  1. However, we only needed to double the input size to
                                                                                                                                                         extension of LLMs, enabling them to retrieve documents that
  achieve a similar reduction in gains, from 86% to -10%. As the
                                                                                                                                                         match queries. RAG embeds documents in an index, which is
  attention part of the model grows quadratically with the input
                                                                                                                                                         then searched during inference for closest matches in a process
  size, it implies a greater impact on compute requirements as
                                                                                                                                                         called retrieval. For example, the Best Matching 25 (BM25) is
  compared to only linear increases for batch size.
     3) Security: While CPU TEEs perform worse than cGPUs                                                                                                a classic retrieval model that ranks documents by keywords.
  with larger input sizes, they have one more advantage: security.                                                                                       Reranked BM25 first retrieves BM25 and then reranks it using
  CPU TEEs are more mature, and their security model is stricter                                                                                         a cross-encoder. For both, an Elasticsearch database [10] is
  than cGPUs. H100s do not encrypt their HBM memory [31],                                                                                                typically used to store the documents. RAG can also involve
  compared to CPUs that do. While in CPU-based systems,                                                                                                  LLMs such as SBERT, which encodes queries and documents
  communication between different sockets is transparently                                                                                               into dense vectors using a pre-trained Sentence-BERT encoder
  encrypted, interconnects such as PCIe and NVLINK do not                                                                                                and ranks matches based on cosine similarity. We evaluate the
  yet have this feature [31], which limits inter-accelerator                                                                                             performance of RAG using these three methods in BEIR [77],
  communication to go through the host. This is crucial for                                                                                              running them and an Elasticsearch database entirely within
  larger models that do not fit on a single GPU. While B100s                                                                                             TDX. Figure 14 shows that even though the RAG workload,
  address these issues, we expect that they will add a non-                                                                                              such as BM25 ranking, differs from a normal LLM inference,
  negligible overhead to H100s’ results, since we identified                                                                                             our results display a similar level of overhead. We observe
  memory encryption as a significant cost in CPUs.                                                                                                       6-7% degradation for TDX, suggesting CPU TEEs might also
     4) Scaling models: We compared the CPUs (fitting 70B                                                                                                be used for these purposes without significant performance
  parameters) to a single GPU (fitting 30B parameters). Scale-                                                                                           impacts. Additionally, knowing that LLM RAG is conducted
  up of confidential H100s is costly due to the aforementioned                                                                                           frequently with a batch size of one and for small models such
  security concerns. Similarly, scaling out through combining                                                                                            as SBERT, we can leverage Insight 11 to deduce that CPU
  single-GPU VMs is currently inefficient. As the cGPU in-                                                                                               TEEs might be more cost-efficient than cGPUs.
  stances do not support RDMA and GPUdirect, all data is                                                                                                        Insight 12: Performance of entire RAG pipeline in TDX
  transferred through the CPU, capping throughput at 3GB/s                                                                                                   achieves similar overheads to the LLM inference.
  (considerably lower than the non-confidential 40GB/s) [89].
  This is costly for throughput-hungry patterns such as pipeline                                                                                                            VII. Related work
  parallelism and tensor parallelism. We expect this to lower                                                                                             TEEs have been investigated in the past for protecting
  the advantage of GPUs over CPUs. A network protection                                                                                                  ML models [57]. Yet, most of these approaches offload only
                                                                   System     Intel SGX (process TEE)        Intel TDX (VM TEE)       H100 cGPU (GPU TEE)
                                                                  Memory                      C                       C              B (HBM unencrypted)
                                   Hardware
                                                                  Scale-up                    C                       C              D (NVLINK unprotected)
             Security                                                 App                 C                           C                        C
                                    Software                           OS               D (libOS)                     C                        C
                                                                      VM                  B                           C                        C
                                   Overhead           Single resource                        ~4-5%                  ~5–10%                    ~4–8%
                                                            Batch size↑                        ↓                       ↓                        ↓
                                  Parameters
                                                            Input size↑                       ↓↑                       ↓↑                       ↓
                                  influencing
   Performance                                                    AMX                         ↓                        ↓                         -
                                   overheads
                                                               Scale-up                       ↑↑                       ↑                        ↑↑
                                                                                       EPC paging,             Virtualization tax,
                                  Sources                                                                                                 PCIe transfers,
                                                                                      enclave exits,               hugepages,
                             of overheads                                                                                                 kernel launch
                                                                                     memory, NUMA              memory, NUMA
                             Development                                                      D                       C                        C
                   Cost            Resource     Small inputs/batches                          C                       C                        D
                                   efficiency   Large inputs/batches                          D                       D                        C

                                                                    TABLE I
   The summary of evaluated systems and the insights. C indicates full/good, D partial, and B no support. ↓ indicates decreasing, ↑ increasing,
                          ↑↑ increasing considerably more than ↑, and ↓↑ first decreasing, then increasing overheads.


   parts of the models to TEEs, providing weaker notions of                                                          VIII. Conclusions
   security and citing low TEE performance as the reason.
   For example, Slalom [80] offloads linear layers to the GPU                                     We investigated several methods for protecting LLM de-
   with a probabilistic algorithm guaranteeing some security.                                  ployments and discussed how TEEs yield a practical balance
   Furthermore, none of these works explored LLMs, focusing                                    between security, performance, and programmability. We
   instead on simpler models due to the extensive model changes.                               demonstrated the viability of securing LLMs with TEEs by
   In contrast, we run an entire LLM inference pipeline in TEEs,                               running an inference pipeline on top of Intel’s TDX and SGX,
   demonstrating their practicality for protecting LLMs.                                       as well as NVIDIA’s H100s. We conducted a thorough study of
                                                                                               the performance of TEEs in these workloads, identifying the
      Some performance studies have been conducted on
                                                                                               best frameworks, sources of overheads, and optimal operating
   SGX [14], [32], [40], [56], [90] and TDX [11], [55]. These
                                                                                               points. We shared 12 key insights, showing, among others,
   focus on quantifying the overheads of the underlying primitive
                                                                                               that CPU TEEs have NUMA and hugepages issues, and
   operations, such as memory overheads, and the performance
                                                                                               how AMX helps improve their performance. We have also
   of certain applications. However, none address workloads as
                                                                                               compared CPU and GPU TEEs in terms of performance, cost-
   compute-intensive as LLMs. Some works that demonstrate
                                                                                               efficiency, and security. Finally, we applied our lessons to a
   secure LLM inference [26] focus more on security, missing the
                                                                                               RAG pipeline within a TEE, demonstrating its performance.
   depth and key deployment insights, such as AMX performance
                                                                                               Table I shows the summary of our investigation. Our results
   improvements, scalability, and cost considerations. Similarly,
                                                                                               show that TEEs impose a manageable performance overhead
   GPUs have been studied for their sources of overhead [58],
                                                                                               on LLM pipelines, demonstrating that TEEs represent a viable
   [89]. However, these outline overheads considerably larger
                                                                                               solution for protecting LLM inference, positioning them as a
   than ours, or do not show raw LLM performance. Additionally,
                                                                                               cornerstone for future confidential AI deployments.
   none compares GPU TEEs to CPU TEEs, thereby failing to
   display the full spectrum of practical deployments.
                                                                                                                     Acknowledgment

               BM25 reranked                     BM25                        sbert               This research was conducted as part of the “UrbanTwin: An
                                          10                         4                         urban digital twin for climate action: Assessing policies and
            2000                                                                               solutions for energy, water and infrastructure” project, funded
Time (ms)




                                  6.03%




                                                                                     7.33%




                                                                                               by ETH-Domain Joint Initiative program in the Strategic
                                                          6.47%
                                                  3.74%
                          2.78%




                                                                             3.08%




            1000                           5                         2
                                                                                               Area Energy, Climate and Sustainable Environment, with
                                                                                               additional support from Intel Corporation. We thank Intel for
          0               0               0                                                    providing hardware resources, Cory Cornelius, Anjo Vahldiek-
              l               l               l
      baremeta VM TDX baremeta VM TDX baremeta VM TDX                                          Oberwagner, Marcin Spoczynski, Scott Constable and Mona
                                                                                               Vij for their valuable feedback, and Madlen Koblinger for
    Fig. 14. Comparison of mean evaluation time for RAG systems on EMR2.                       assisting with the design of figures.
                               References                                               “Extracting Training Data from Large Language Models,” in 30th USENIX
                                                                                        Security Symposium (USENIX Security 21), 2021, pp. 2633–2650.
 [1] “Announcing Azure confidential VMs with NVIDIA H100 Tensor                    [23] P.-C. Cheng, W. Ozga, E. Valdez, S. Ahmed, Z. Gu, H. Jamjoom, H. Franke,
     Core GPUs in Preview,” https://techcommunity.microsoft.com/t5/azure-               and J. Bottomley, “Intel TDX Demystified: A Top-Down Approach,” ACM
     confidential-computing/announcing-azure-confidential-vms-with-                     Computing Surveys, Mar. 2024.
     nvidia-h100-tensor-core/ba-p/3975389.                                         [24] M. Chrapek, M. Khalilov, and T. Hoefler, “HEAR: Homomorphically
 [2] “IDE and TDISP: An Overview of PCIe® Technology Security Features                  Encrypted Allreduce,” in Proceedings of the International Conference for
     | PCI-SIG,” https://pcisig.com/blog/ide-and-tdisp-overview-pcie%C2%AE-             High Performance Computing, Networking, Storage and Analysis, ser. SC
     technology-security-features.                                                      ’23. New York, NY, USA: Association for Computing Machinery, Nov.
 [3] “Intel®        Xeon®          Gold        6530      Processor       (160M          2023, pp. 1–17.
     Cache,         2.10       GHz)       -        Product      Specifications,”   [25] M. Chrapek, S. Shen, P. Iff, T. Chen, M. Khalilov, M. Copik, M. Besta,
     https://www.intel.com/content/www/us/en/products/sku/237249/intel-                 and T. Hoefler, “Secperf: Demystifying the cost of confidential compute,”
     xeon-gold-6530-processor-160m-cache-2-10-ghz/specifications.html.                  2025.
 [4] “Intel®       Xeon®         Platinum        8580     Processor      (300M     [26] M. Chrapek, A. Vahldiek-Oberwagner, M. Spoczynski, S. Constable,
     Cache,         2.00       GHz)       -        Product      Specifications,”        M. Vij, and T. Hoefler, “Fortify Your Foundations: Practical Privacy and
     https://www.intel.com/content/www/us/en/products/sku/237250/intel-                 Security for Foundation Model Deployments In The Cloud,” Oct. 2024.
     xeon-platinum-8580-processor-300m-cache-2-00-                                 [27] L. Coppolino, S. D’Antonio, G. Mazzeo, and L. Romano, “An experimental
     ghz/specifications.html.                                                           evaluation of TEE technology: Benchmarking transparent approaches
 [5] “The Llama 4 herd: The beginning of a new era of natively mul-                     based on SGX, SEV, and TDX,” Computers & Security, vol. 154, p. 104457,
     timodal AI innovation,” https://ai.meta.com/blog/llama-4-multimodal-               Jul. 2025.
     intelligence/.                                                                [28] V. Costan and S. Devadas, “Intel SGX Explained,” 2016.
 [6] “NVIDIA         H100       NVL      94GB        |    ASA      Computers,”     [29] J. Cui, Z. Li, Y. Yan, B. Chen, and L. Yuan, “ChatLaw: Open-Source Legal
     https://www.asacomputers.com/nvidia-h100-nvl-94gb-graphics-                        Large Language Model with Integrated External Knowledge Bases,” Jun.
     card.html.                                                                         2023.
 [7] “Privacy-preserving Confidential Computing now on even                        [30] L. Dagum and R. Menon, “OpenMP: An industry standard API for shared-
     more machines,” https://cloud.google.com/blog/products/identity-                   memory programming,” IEEE Computational Science and Engineering,
     security/privacy-preserving-confidential-computing-now-on-even-                    vol. 5, no. 1, pp. 46–55, Jan. 1998.
     more-machines.                                                                [31] G. Dhanuskodi, S. Guha, V. Krishnan, A. Manjunatha, M. O’Connor,
 [8] “Samsung Bans Generative AI Use by Staff After ChatGPT Data Leak,”                 R. Nertney, and P. Rogers, “Creating the First Confidential GPUs: The
     Bloomberg.com, May 2023.                                                           team at NVIDIA brings confidentiality and integrity to user code and
                                                                                        data for accelerated computing.” Queue, vol. 21, no. 4, pp. Pages 40:68–
 [9] “SEV-TIO Firmware Interface Specification,” Tech. Rep., 2023.
                                                                                        Pages 40:93, Sep. 2023.
[10] “Elastic/elasticsearch,” elastic, May 2025.
                                                                                   [32] T. Dinh Ngoc, B. Bui, S. Bitchebe, A. Tchana, V. Schiavoni, P. Felber,
[11] “An experimental evaluation of TEE technology: Benchmarking trans-                 and D. Hagimont, “Everything You Should Know About Intel SGX
     parent approaches based on SGX, SEV, and TDX,” Computers & Security,               Performance on Virtualized Systems,” Proc. ACM Meas. Anal. Comput.
     vol. 154, p. 104457, Jul. 2025.                                                    Syst., vol. 3, no. 1, pp. 5:1–5:21, Mar. 2019.
[12] “Ggml-org/llama.cpp,” ggml, May 2025.                                         [33] N. Dowlin, R. Gilad-Bachrach, K. Laine, K. Lauter, M. Naehrig, and
[13] A. Acar, H. Aksu, A. S. Uluagac, and M. Conti, “A Survey on                        J. Wernsing, “CryptoNets: Applying Neural Networks to Encrypted
     Homomorphic Encryption Schemes: Theory and Implementation,” ACM                    Data with High Throughput and Accuracy.”
     Computing Surveys, vol. 51, no. 4, pp. 79:1–79:35, Jul. 2018.                 [34] D. Durner, V. Leis, and T. Neumann, “On the Impact of Memory
[14] A. Akram, A. Giannakou, V. Akella, J. Lowe-Power, and S. Peisert,                  Allocation on High-Performance Query Processing,” in Proceedings of
     “Performance Analysis of Scientific Computing Workloads on General                 the 15th International Workshop on Data Management on New Hardware,
     Purpose TEEs,” in 2021 IEEE International Parallel and Distributed                 ser. DaMoN’19. New York, NY, USA: Association for Computing
     Processing Symposium (IPDPS), May 2021, pp. 1066–1076.                             Machinery, Jul. 2019, pp. 1–3.
[15] R. Y. Aminabadi, S. Rajbhandari, A. A. Awan, C. Li, D. Li, E. Zheng,          [35] D. Eadline, “Intel Won’t Have a Xeon Max Chip with New Emerald
     O. Ruwase, S. Smith, M. Zhang, J. Rasley, and Y. He, “DeepSpeed-                   Rapids CPU,” https://www.hpcwire.com/2023/12/14/intel-wont-have-a-
     Inference: Enabling Efficient Inference of Transformer Models at                   xeon-max-chip-with-new-emerald-rapids-cpu/, Dec. 2023.
     Unprecedented Scale,” in SC22: International Conference for High              [36] A. Ebel, K. Garimella, and B. Reagen, “Orion: A Fully Homomorphic
     Performance Computing, Networking, Storage and Analysis, Nov. 2022,                Encryption Framework for Deep Learning,” in Proceedings of the 30th
     pp. 1–15.                                                                          ACM International Conference on Architectural Support for Programming
[16] D. Araci, “FinBERT: Financial Sentiment Analysis with Pre-trained                  Languages and Operating Systems, Volume 2, ser. ASPLOS ’25. New
     Language Models,” Aug. 2019.                                                       York, NY, USA: Association for Computing Machinery, Mar. 2025, pp.
[17] S. Arnautov, B. Trach, F. Gregor, T. Knauth, A. Martin, C. Priebe, J. Lind,        734–749.
     D. Muthukumaran, D. O’Keeffe, M. L. Stillwell, D. Goltzsche, D. Eyers,        [37] L. Fan, K. W. Ng, and C. S. Chan, “Rethinking Deep Neural Network
     R. Kapitza, P. Pietzuch, and C. Fetzer, “{SCONE}: Secure Linux Containers          Ownership Verification: Embedding Passports to Defeat Ambiguity
     with Intel {SGX},” in 12th USENIX Symposium on Operating Systems                   Attacks,” in Advances in Neural Information Processing Systems, vol. 32.
     Design and Implementation (OSDI 16), 2016, pp. 689–703.                            Curran Associates, Inc., 2019.
[18] M. Awais, M. Naseer, S. Khan, R. M. Anwer, H. Cholakkal, M. Shah,             [38] C. Fruhwirth, “LUKS on-disk format specification version 1.2.” 2011.
     M.-H. Yang, and F. S. Khan, “Foundational Models Defining a New Era           [39] Y. Gao, Y. Xiong, X. Gao, K. Jia, J. Pan, Y. Bi, Y. Dai, J. Sun, M. Wang,
     in Vision: A Survey and Outlook,” Jul. 2023.                                       and H. Wang, “Retrieval-Augmented Generation for Large Language
[19] F. Boenisch, “A Systematic Review on Model Watermarking for Neural                 Models: A Survey,” Mar. 2024.
     Networks,” Frontiers in Big Data, vol. 4, p. 729663, Nov. 2021.               [40] A. T. Gjerdrum, R. Pettersen, H. D. Johansen, and D. Johansen,
[20] T. B. Brown, B. Mann, N. Ryder, M. Subbiah, J. Kaplan, P. Dhariwal,                “Performance of Trusted Computing in Cloud Infrastructures with
     A. Neelakantan, P. Shyam, G. Sastry, A. Askell, S. Agarwal, A. Herbert-            Intel SGX,” in Proceedings of the 7th International Conference on Cloud
     Voss, G. Krueger, T. Henighan, R. Child, A. Ramesh, D. M. Ziegler,                 Computing and Services Science, ser. CLOSER 2017. Setubal, PRT:
     J. Wu, C. Winter, C. Hesse, M. Chen, E. Sigler, M. Litwin, S. Gray,                SCITEPRESS - Science and Technology Publications, Lda, Apr. 2017, pp.
     B. Chess, J. Clark, C. Berner, S. McCandlish, A. Radford, I. Sutskever,            696–703.
     and D. Amodei, “Language Models are Few-Shot Learners,” Jul. 2020.            [41] A. Grattafiori, A. Dubey, A. Jauhri, A. Pandey, A. Kadian, A. Al-
[21] L. Burkhalter, A. Hithnawi, A. Viand, H. Shafagh, and S. Ratnasamy,                Dahle, A. Letman, A. Mathur, A. Schelten, A. Vaughan, A. Yang,
     “{TimeCrypt}: Encrypted Data Stream Processing at Scale with Cryp-                 A. Fan, A. Goyal, A. Hartshorn, A. Yang, A. Mitra, A. Sravankumar,
     tographic Access Control,” in 17th USENIX Symposium on Networked                   A. Korenev, A. Hinsvark, A. Rao, A. Zhang, A. Rodriguez, A. Gregerson,
     Systems Design and Implementation (NSDI 20), 2020, pp. 835–850.                    A. Spataru, B. Roziere, B. Biron, B. Tang, B. Chern, C. Caucheteux,
[22] N. Carlini, F. Tramèr, E. Wallace, M. Jagielski, A. Herbert-Voss, K. Lee,          C. Nayak, C. Bi, C. Marra, C. McConnell, C. Keller, C. Touret, C. Wu,
     A. Roberts, T. Brown, D. Song, Ú. Erlingsson, A. Oprea, and C. Raffel,             C. Wong, C. C. Ferrer, C. Nikolaidis, D. Allonsius, D. Song, D. Pintz,
D. Livshits, D. Wyatt, D. Esiobu, D. Choudhary, D. Mahajan, D. Garcia-               T. Zhang, T. Matthews, T. Chou, T. Shaked, V. Vontimitta, V. Ajayi,
Olano, D. Perino, D. Hupkes, E. Lakomkin, E. AlBadawy, E. Lobanova,                  V. Montanez, V. Mohan, V. S. Kumar, V. Mangla, V. Ionescu, V. Poenaru,
E. Dinan, E. M. Smith, F. Radenovic, F. Guzmán, F. Zhang, G. Synnaeve,               V. T. Mihailescu, V. Ivanov, W. Li, W. Wang, W. Jiang, W. Bouaziz,
G. Lee, G. L. Anderson, G. Thattai, G. Nail, G. Mialon, G. Pang,                     W. Constable, X. Tang, X. Wu, X. Wang, X. Wu, X. Gao, Y. Kleinman,
G. Cucurell, H. Nguyen, H. Korevaar, H. Xu, H. Touvron, I. Zarov,                    Y. Chen, Y. Hu, Y. Jia, Y. Qi, Y. Li, Y. Zhang, Y. Zhang, Y. Adi, Y. Nam,
I. A. Ibarra, I. Kloumann, I. Misra, I. Evtimov, J. Zhang, J. Copet, J. Lee,         Yu, Wang, Y. Zhao, Y. Hao, Y. Qian, Y. Li, Y. He, Z. Rait, Z. DeVito,
J. Geffert, J. Vranes, J. Park, J. Mahadeokar, J. Shah, J. van der Linde,            Z. Rosnbrick, Z. Wen, Z. Yang, Z. Zhao, and Z. Ma, “The Llama 3 Herd
J. Billock, J. Hong, J. Lee, J. Fu, J. Chi, J. Huang, J. Liu, J. Wang,               of Models,” Nov. 2024.
J. Yu, J. Bitton, J. Spisak, J. Park, J. Rocca, J. Johnstun, J. Saxe, J. Jia,   [42] M. Hoekstra, R. Lal, P. Pappachan, V. Phegade, and J. Del Cuvillo,
K. V. Alwala, K. Prasad, K. Upasani, K. Plawiak, K. Li, K. Heafield,                 “Using innovative instructions to create trustworthy software solutions,”
K. Stone, K. El-Arini, K. Iyer, K. Malik, K. Chiu, K. Bhalla, K. Lakhotia,           in Proceedings of the 2nd International Workshop on Hardware and
L. Rantala-Yeary, L. van der Maaten, L. Chen, L. Tan, L. Jenkins,                    Architectural Support for Security and Privacy, ser. HASP ’13. New
L. Martin, L. Madaan, L. Malo, L. Blecher, L. Landzaat, L. de Oliveira,              York, NY, USA: Association for Computing Machinery, Jun. 2013, p. 1.
M. Muzzi, M. Pasupuleti, M. Singh, M. Paluri, M. Kardas, M. Tsimpoukelli,       [43] A. Ivanov, N. Dryden, T. Ben-Nun, S. Li, and T. Hoefler, “Data Movement
M. Oldham, M. Rita, M. Pavlova, M. Kambadur, M. Lewis, M. Si, M. K.                  Is All You Need: A Case Study on Optimizing Transformers,” Proceedings
Singh, M. Hassan, N. Goyal, N. Torabi, N. Bashlykov, N. Bogoychev,                   of Machine Learning and Systems, vol. 3, pp. 711–732, Mar. 2021.
N. Chatterji, N. Zhang, O. Duchenne, O. Çelebi, P. Alrassy, P. Zhang,           [44] S. Johnson, R. Makaram, A. Santoni, and V. Scarlata, “Supporting intel®
P. Li, P. Vasic, P. Weng, P. Bhargava, P. Dubal, P. Krishnan, P. S.                  SGX on multi-socket platforms,” Intel Corporation, Tech. Rep. 843058,
Koura, P. Xu, Q. He, Q. Dong, R. Srinivasan, R. Ganapathy, R. Calderer,              Dec. 2024.
R. S. Cabral, R. Stojnic, R. Raileanu, R. Maheswari, R. Girdhar, R. Patel,      [45] D. Kaplan, “AMD SEV-SNP: Strengthening VM Isolation with Integrity
R. Sauvestre, R. Polidoro, R. Sumbaly, R. Taylor, R. Silva, R. Hou, R. Wang,         Protection and More.”
S. Hosseini, S. Chennabasappa, S. Singh, S. Bell, S. S. Kim, S. Edunov,         [46] B. Knott, S. Venkataraman, A. Hannun, S. Sengupta, M. Ibrahim, and
S. Nie, S. Narang, S. Raparthy, S. Shen, S. Wan, S. Bhosale, S. Zhang,               L. van der Maaten, “CrypTen: Secure Multi-Party Computation Meets
S. Vandenhende, S. Batra, S. Whitman, S. Sootla, S. Collot, S. Gururangan,           Machine Learning,” Sep. 2022.
S. Borodinsky, T. Herman, T. Fowler, T. Sheasha, T. Georgiou, T. Scialom,
                                                                                [47] T. Kocmi and C. Federmann, “Large Language Models Are State-of-the-
T. Speckbacher, T. Mihaylov, T. Xiao, U. Karn, V. Goswami, V. Gupta,
                                                                                     Art Evaluators of Translation Quality,” May 2023.
V. Ramanathan, V. Kerkez, V. Gonguet, V. Do, V. Vogeti, V. Albiero,
                                                                                [48] W. Kwon, Z. Li, S. Zhuang, Y. Sheng, L. Zheng, C. H. Yu, J. Gonzalez,
V. Petrovic, W. Chu, W. Xiong, W. Fu, W. Meers, X. Martinet, X. Wang,
                                                                                     H. Zhang, and I. Stoica, “Efficient memory management for large
X. Wang, X. E. Tan, X. Xia, X. Xie, X. Jia, X. Wang, Y. Goldschlag,
                                                                                     language model serving with pagedattention,” in Proceedings of the
Y. Gaur, Y. Babaei, Y. Wen, Y. Song, Y. Zhang, Y. Li, Y. Mao, Z. D. Coudert,
                                                                                     29th Symposium on Operating Systems Principles, 2023, pp. 611–626.
Z. Yan, Z. Chen, Z. Papakipos, A. Singh, A. Srivastava, A. Jain, A. Kelsey,
A. Shajnfeld, A. Gangidi, A. Victoria, A. Goldstand, A. Menon, A. Sharma,       [49] Y. Lao, W. Zhao, P. Yang, and P. Li, “DeepAuth: A DNN Authentication
A. Boesenberg, A. Baevski, A. Feinstein, A. Kallet, A. Sangani, A. Teo,              Framework by Model-Unique and Fragile Signature Embedding,” Pro-
A. Yunus, A. Lupu, A. Alvarado, A. Caples, A. Gu, A. Ho, A. Poulton,                 ceedings of the AAAI Conference on Artificial Intelligence, vol. 36, no. 9,
A. Ryan, A. Ramchandani, A. Dong, A. Franco, A. Goyal, A. Saraf,                     pp. 9595–9603, Jun. 2022.
A. Chowdhury, A. Gabriel, A. Bharambe, A. Eisenman, A. Yazdan,                  [50] D. Lee, D. Kohlbrenner, S. Shinde, K. Asanović, and D. Song, “Keystone:
B. James, B. Maurer, B. Leonhardi, B. Huang, B. Loyd, B. D. Paola,                   An open framework for architecting trusted execution environments,”
B. Paranjape, B. Liu, B. Wu, B. Ni, B. Hancock, B. Wasti, B. Spence,                 in Proceedings of the Fifteenth European Conference on Computer Systems,
B. Stojkovic, B. Gamido, B. Montalvo, C. Parker, C. Burton, C. Mejia,                ser. EuroSys ’20. New York, NY, USA: Association for Computing
C. Liu, C. Wang, C. Kim, C. Zhou, C. Hu, C.-H. Chu, C. Cai, C. Tindal,               Machinery, Apr. 2020, pp. 1–16.
C. Feichtenhofer, C. Gao, D. Civin, D. Beaty, D. Kreymer, D. Li, D. Adkins,     [51] J.-W. Lee, H. Kang, Y. Lee, W. Choi, J. Eom, M. Deryabin, E. Lee, J. Lee,
D. Xu, D. Testuggine, D. David, D. Parikh, D. Liskovich, D. Foss,                    D. Yoo, Y.-S. Kim, and J.-S. No, “Privacy-Preserving Machine Learning
D. Wang, D. Le, D. Holland, E. Dowling, E. Jamil, E. Montgomery,                     With Fully Homomorphic Encryption for Deep Neural Network,” IEEE
E. Presani, E. Hahn, E. Wood, E.-T. Le, E. Brinkman, E. Arcaute,                     Access, vol. 10, pp. 30 039–30 054, 2022.
E. Dunbar, E. Smothers, F. Sun, F. Kreuk, F. Tian, F. Kokkinos,                 [52] B. Li, V. Gadepally, S. Samsi, and D. Tiwari, “Characterizing Multi-
F. Ozgenel, F. Caggioni, F. Kanayet, F. Seide, G. M. Florez, G. Schwarz,             Instance GPU for Machine Learning Workloads,” in 2022 IEEE In-
G. Badeer, G. Swee, G. Halpern, G. Herman, G. Sizov, Guangyi, Zhang,                 ternational Parallel and Distributed Processing Symposium Workshops
G. Lakshminarayanan, H. Inan, H. Shojanazeri, H. Zou, H. Wang,                       (IPDPSW), May 2022, pp. 724–731.
H. Zha, H. Habeeb, H. Rudolph, H. Suk, H. Aspegren, H. Goldman,                 [53] X. Li, X. Li, C. Dall, R. Gu, J. Nieh, Y. Sait, and G. Stockwell, “Design
H. Zhan, I. Damlaj, I. Molybog, I. Tufanov, I. Leontiadis, I.-E. Veliche,            and Verification of the Arm Confidential Compute Architecture,” in 16th
I. Gat, J. Weissman, J. Geboski, J. Kohli, J. Lam, J. Asher, J.-B. Gaya,             USENIX Symposium on Operating Systems Design and Implementation
J. Marcus, J. Tang, J. Chan, J. Zhen, J. Reizenstein, J. Teboul, J. Zhong,           (OSDI 22), 2022, pp. 465–484.
J. Jin, J. Yang, J. Cummings, J. Carvill, J. Shepard, J. McPhie, J. Torres,     [54] F. McKeen, I. Alexandrovich, A. Berenzon, C. V. Rozas, H. Shafi,
J. Ginsburg, J. Wang, K. Wu, K. H. U, K. Saxena, K. Khandelwal, K. Zand,             V. Shanbhogue, and U. R. Savagaonkar, “Innovative instructions and
K. Matosich, K. Veeraraghavan, K. Michelena, K. Li, K. Jagadeesh,                    software model for isolated execution,” in Proceedings of the 2nd
K. Huang, K. Chawla, K. Huang, L. Chen, L. Garg, L. A, L. Silva, L. Bell,            International Workshop on Hardware and Architectural Support for
L. Zhang, L. Guo, L. Yu, L. Moshkovich, L. Wehrstedt, M. Khabsa,                     Security and Privacy, ser. HASP ’13. New York, NY, USA: Association
M. Avalani, M. Bhatt, M. Mankus, M. Hasson, M. Lennie, M. Reso,                      for Computing Machinery, Jun. 2013, p. 1.
M. Groshev, M. Naumov, M. Lathi, M. Keneally, M. Liu, M. L. Seltzer,            [55] M. Misono, D. Stavrakakis, N. Santos, and P. Bhatotia, “Confidential
M. Valko, M. Restrepo, M. Patel, M. Vyatskov, M. Samvelyan, M. Clark,                VMs Explained: An Empirical Analysis of AMD SEV-SNP and Intel
M. Macey, M. Wang, M. J. Hermoso, M. Metanat, M. Rastegari, M. Bansal,               TDX,” Proc. ACM Meas. Anal. Comput. Syst., vol. 8, no. 3, pp. 36:1–36:42,
N. Santhanam, N. Parks, N. White, N. Bawa, N. Singhal, N. Egebo,                     Dec. 2024.
N. Usunier, N. Mehta, N. P. Laptev, N. Dong, N. Cheng, O. Chernoguz,            [56] S. Miwa and S. Matsuo, “Analyzing the Performance Impact of HPC
O. Hart, O. Salpekar, O. Kalinli, P. Kent, P. Parekh, P. Saab, P. Balaji,            Workloads with Gramine+SGX on 3rd Generation Xeon Scalable
P. Rittner, P. Bontrager, P. Roux, P. Dollar, P. Zvyagina, P. Ratanchandani,         Processors,” in Proceedings of the SC ’23 Workshops of the International
P. Yuvraj, Q. Liang, R. Alao, R. Rodriguez, R. Ayub, R. Murthy, R. Nayani,           Conference on High Performance Computing, Network, Storage, and
R. Mitra, R. Parthasarathy, R. Li, R. Hogan, R. Battey, R. Wang, R. Howes,           Analysis, ser. SC-W ’23. New York, NY, USA: Association for Computing
R. Rinott, S. Mehta, S. Siby, S. J. Bondu, S. Datta, S. Chugh, S. Hunt,              Machinery, Nov. 2023, pp. 1850–1858.
S. Dhillon, S. Sidorov, S. Pan, S. Mahajan, S. Verma, S. Yamamoto,              [57] F. Mo, Z. Tarkhani, and H. Haddadi, “Machine Learning with Confiden-
S. Ramaswamy, S. Lindsay, S. Lindsay, S. Feng, S. Lin, S. C. Zha, S. Patil,          tial Computing: A Systematization of Knowledge,” Apr. 2023.
S. Shankar, S. Zhang, S. Zhang, S. Wang, S. Agarwal, S. Sajuyigbe,              [58] A. Mohan, M. Ye, H. Franke, M. Srivatsa, Z. Liu, and N. M. Gonzalez,
S. Chintala, S. Max, S. Chen, S. Kehoe, S. Satterfield, S. Govindaprasad,            “Securing AI Inference in the Cloud: Is CPU-GPU Confidential Com-
S. Gupta, S. Deng, S. Cho, S. Virk, S. Subramanian, S. Choudhury,                    puting Ready?” in 2024 IEEE 17th International Conference on Cloud
S. Goldman, T. Remez, T. Glaser, T. Best, T. Koehler, T. Robinson, T. Li,            Computing (CLOUD). IEEE Computer Society, Jul. 2024, pp. 164–175.
[59] D. P. Mulligan, G. Petri, N. Spinale, G. Stockwell, and H. J. M. Vincent, [68] R. Pope, S. Douglas, A. Chowdhery, J. Devlin, J. Bradbury, J. Heek,
     “Confidential Computing—a brave new world,” in 2021 International                      K. Xiao, S. Agrawal, and J. Dean, “Efficiently Scaling Transformer
     Symposium on Secure and Private Execution Environment Design (SEED),                   Inference,” Proceedings of Machine Learning and Systems, vol. 5, pp.
     Sep. 2021, pp. 132–138.                                                                606–624, Mar. 2023.
[60] D.          L.        Mulnix,         “Intel®            Xeon®          Proces- [69] K. Rayner, E. R. Schotter, M. E. J. Masson, M. C. Potter, and R. Treiman,
     sor          Scalable          Family           Technical           Overview,”         “So Much to Read, So Little Time: How Do We Read, and Can Speed
     https://www.intel.com/content/www/us/en/developer/articles/technical/xeon-             Reading Help?” Psychological Science in the Public Interest, vol. 17, no. 1,
     processor-scalable-family-technical-overview.html.                                     pp. 4–34, May 2016.
[61] S. Na, G. Jeong, B. H. Ahn, J. Young, T. Krishna, and H. Kim, [70] M. Sabt, M. Achemlal, and A. Bouabdallah, “Trusted Execution En-
     “Understanding Performance Implications of LLM Inference on CPUs,”                     vironment: What It is, and What It is Not,” in 2015 IEEE Trust-
     in 2024 IEEE International Symposium on Workload Characterization                      com/BigDataSE/ISPA, vol. 1, Aug. 2015, pp. 57–64.
     (IISWC), Sep. 2024, pp. 169–180.                                                  [71] M. Sallam, “ChatGPT Utility in Healthcare Education, Research, and
[62] R. Nertney, “Confidential Compute on NVIDIA Hopper H100 - Whitepa-                     Practice: Systematic Review on the Promising Perspectives and Valid
     per,” Tech. Rep., Jul. 2023.                                                           Concerns,” Healthcare, vol. 11, no. 6, p. 887, Jan. 2023.
                                                                                       [72] C. Segarra, T. Feldman-Fitzthum, D. Buono, and P. Pietzuch, “Serverless
[63] T. Ng, “Adobe Says It Won’t Train AI Using Artists’ Work. Creatives                    Confidential Containers: Challenges and Opportunities,” in Proceedings of
     Aren’t Convinced,” Wired.                                                              the 2nd Workshop on SErverless Systems, Applications and MEthodologies,
[64] OpenAI, J. Achiam, S. Adler, S. Agarwal, L. Ahmad, I. Akkaya,                          ser. SESAME ’24. New York, NY, USA: Association for Computing
     F. L. Aleman, D. Almeida, J. Altenschmidt, S. Altman, S. Anadkat,                      Machinery, Apr. 2024, pp. 32–40.
     R. Avila, I. Babuschkin, S. Balaji, V. Balcom, P. Baltescu, H. Bao, [73] O. Sharir, B. Peleg, and Y. Shoham, “The Cost of Training NLP Models:
     M. Bavarian, J. Belgum, I. Bello, J. Berdine, G. Bernadett-Shapiro,                    A Concise Overview,” Apr. 2020.
     C. Berner, L. Bogdonoff, O. Boiko, M. Boyd, A.-L. Brakman, G. Brockman, [74] Y. Shen, H. Tian, Y. Chen, K. Chen, R. Wang, Y. Xu, Y. Xia, and S. Yan,
     T. Brooks, M. Brundage, K. Button, T. Cai, R. Campbell, A. Cann,                       “Occlum: Secure and Efficient Multitasking Inside a Single Enclave of
     B. Carey, C. Carlson, R. Carmichael, B. Chan, C. Chang, F. Chantzis,                   Intel SGX,” in Proceedings of the Twenty-Fifth International Conference on
     D. Chen, S. Chen, R. Chen, J. Chen, M. Chen, B. Chess, C. Cho, C. Chu,                 Architectural Support for Programming Languages and Operating Systems,
     H. W. Chung, D. Cummings, J. Currier, Y. Dai, C. Decareaux, T. Degry,                  ser. ASPLOS ’20. New York, NY, USA: Association for Computing
     N. Deutsch, D. Deville, A. Dhar, D. Dohan, S. Dowling, S. Dunning,                     Machinery, Mar. 2020, pp. 955–970.
     A. Ecoffet, A. Eleti, T. Eloundou, D. Farhi, L. Fedus, N. Felix, S. P. Fishman, [75] S. Szyller and N. Asokan, “Conflicting interactions among protection
     J. Forte, I. Fulford, L. Gao, E. Georges, C. Gibson, V. Goel, T. Gogineni,             mechanisms for machine learning models,” in Proceedings of the Thirty-
     G. Goh, R. Gontijo-Lopes, J. Gordon, M. Grafstein, S. Gray, R. Greene,                 Seventh AAAI Conference on Artificial Intelligence and Thirty-Fifth
     J. Gross, S. S. Gu, Y. Guo, C. Hallacy, J. Han, J. Harris, Y. He, M. Heaton,           Conference on Innovative Applications of Artificial Intelligence and
     J. Heidecke, C. Hesse, A. Hickey, W. Hickey, P. Hoeschele, B. Houghton,                Thirteenth Symposium on Educational Advances in Artificial Intelligence,
     K. Hsu, S. Hu, X. Hu, J. Huizinga, S. Jain, S. Jain, J. Jang, A. Jiang, R. Jiang,      ser. AAAI’23/IAAI’23/EAAI’23, vol. 37. AAAI Press, Feb. 2023, pp.
     H. Jin, D. Jin, S. Jomoto, B. Jonn, H. Jun, T. Kaftan, Ł. Kaiser, A. Kamali,           15 179–15 187.
     I. Kanitscheider, N. S. Keskar, T. Khan, L. Kilpatrick, J. W. Kim, C. Kim, [76] S. Szyller, B. G. Atli, S. Marchal, and N. Asokan, “DAWN: Dynamic
     Y. Kim, H. Kirchner, J. Kiros, M. Knight, D. Kokotajlo, Ł. Kondraciuk,                 Adversarial Watermarking of Neural Networks,” in Proceedings of the
     A. Kondrich, A. Konstantinidis, K. Kosic, G. Krueger, V. Kuo, M. Lampe,                29th ACM International Conference on Multimedia, ser. MM ’21. New
     I. Lan, T. Lee, J. Leike, J. Leung, D. Levy, C. M. Li, R. Lim, M. Lin,                 York, NY, USA: Association for Computing Machinery, Oct. 2021, pp.
     S. Lin, M. Litwin, T. Lopez, R. Lowe, P. Lue, A. Makanju, K. Malfacini,                4417–4425.
     S. Manning, T. Markov, Y. Markovski, B. Martin, K. Mayer, A. Mayne, [77] N. Thakur, N. Reimers, A. Rücklé, A. Srivastava, and I. Gurevych, “BEIR:
     B. McGrew, S. M. McKinney, C. McLeavey, P. McMillan, J. McNeil,                        A Heterogeneous Benchmark for Zero-shot Evaluation of Information
     D. Medina, A. Mehta, J. Menick, L. Metz, A. Mishchenko, P. Mishkin,                    Retrieval Models,” in Thirty-Fifth Conference on Neural Information
     V. Monaco, E. Morikawa, D. Mossing, T. Mu, M. Murati, O. Murk,                         Processing Systems Datasets and Benchmarks Track (Round 2), Aug. 2021.
     D. Mély, A. Nair, R. Nakano, R. Nayak, A. Neelakantan, R. Ngo, H. Noh, [78] H. Touvron, T. Lavril, G. Izacard, X. Martinet, M.-A. Lachaux, T. Lacroix,
     L. Ouyang, C. O’Keefe, J. Pachocki, A. Paino, J. Palermo, A. Pantuliano,               B. Rozière, N. Goyal, E. Hambro, F. Azhar, A. Rodriguez, A. Joulin,
     G. Parascandolo, J. Parish, E. Parparita, A. Passos, M. Pavlov, A. Peng,               E. Grave, and G. Lample, “LLaMA: Open and Efficient Foundation
     A. Perelman, F. d. A. B. Peres, M. Petrov, H. P. d. O. Pinto, Michael,                 Language Models,” Feb. 2023.
     Pokorny, M. Pokrass, V. Pong, T. Powell, A. Power, B. Power, E. Proehl, [79] H. Touvron, L. Martin, K. Stone, P. Albert, A. Almahairi, Y. Babaei,
     R. Puri, A. Radford, J. Rae, A. Ramesh, C. Raymond, F. Real, K. Rimbach,               N. Bashlykov, S. Batra, P. Bhargava, S. Bhosale, D. Bikel, L. Blecher,
     C. Ross, B. Rotsted, H. Roussez, N. Ryder, M. Saltarelli, T. Sanders,                  C. C. Ferrer, M. Chen, G. Cucurull, D. Esiobu, J. Fernandes, J. Fu, W. Fu,
     S. Santurkar, G. Sastry, H. Schmidt, D. Schnurr, J. Schulman, D. Selsam,               B. Fuller, C. Gao, V. Goswami, N. Goyal, A. Hartshorn, S. Hosseini,
     K. Sheppard, T. Sherbakov, J. Shieh, S. Shoker, P. Shyam, S. Sidor,                    R. Hou, H. Inan, M. Kardas, V. Kerkez, M. Khabsa, I. Kloumann,
     E. Sigler, M. Simens, J. Sitkin, K. Slama, I. Sohl, B. Sokolowsky,                     A. Korenev, P. S. Koura, M.-A. Lachaux, T. Lavril, J. Lee, D. Liskovich,
     Y. Song, N. Staudacher, F. P. Such, N. Summers, I. Sutskever, J. Tang,                 Y. Lu, Y. Mao, X. Martinet, T. Mihaylov, P. Mishra, I. Molybog, Y. Nie,
     N. Tezak, M. Thompson, P. Tillet, A. Tootoonchian, E. Tseng, P. Tuggle,                A. Poulton, J. Reizenstein, R. Rungta, K. Saladi, A. Schelten, R. Silva,
     N. Turley, J. Tworek, J. F. C. Uribe, A. Vallone, A. Vijayvergiya, C. Voss,            E. M. Smith, R. Subramanian, X. E. Tan, B. Tang, R. Taylor, A. Williams,
     C. Wainwright, J. J. Wang, A. Wang, B. Wang, J. Ward, J. Wei, C. J.                    J. X. Kuan, P. Xu, Z. Yan, I. Zarov, Y. Zhang, A. Fan, M. Kambadur,
     Weinmann, A. Welihinda, P. Welinder, J. Weng, L. Weng, M. Wiethoff,                    S. Narang, A. Rodriguez, R. Stojnic, S. Edunov, and T. Scialom, “Llama
     D. Willner, C. Winter, S. Wolrich, H. Wong, L. Workman, S. Wu, J. Wu,                  2: Open Foundation and Fine-Tuned Chat Models,” Jul. 2023.
     M. Wu, K. Xiao, T. Xu, S. Yoo, K. Yu, Q. Yuan, W. Zaremba, R. Zellers, [80] F. Tramèr and D. Boneh, “Slalom: Fast, Verifiable and Private Execution
     C. Zhang, M. Zhang, S. Zhao, T. Zheng, J. Zhuang, W. Zhuk, and                         of Neural Networks in Trusted Hardware,” Feb. 2019.
     B. Zoph, “GPT-4 Technical Report,” Dec. 2023.
                                                                                       [81] C.-C. Tsai, D. E. Porter, and M. Vij, “{Graphene-SGX}: A Practical Library
[65] A. Panwar, A. Prasad, and K. Gopinath, “Making Huge Pages Actually                     {OS} for Unmodified Applications on {SGX},” in 2017 USENIX Annual
     Useful,” in Proceedings of the Twenty-Third International Conference on                Technical Conference (USENIX ATC 17), 2017, pp. 645–658.
     Architectural Support for Programming Languages and Operating Systems, [82] A. Viand and H. Shafagh, “Marble: Making Fully Homomorphic
     ser. ASPLOS ’18. New York, NY, USA: Association for Computing                          Encryption Accessible to All,” in Proceedings of the 6th Workshop on
     Machinery, Mar. 2018, pp. 679–692.                                                     Encrypted Computing & Applied Homomorphic Cryptography, ser. WAHC
[66] V. Patil, P. Hase, and M. Bansal, “Can Sensitive Information Be Deleted                ’18. New York, NY, USA: Association for Computing Machinery, Jan.
     From LLMs? Objectives for Defending Against Extraction Attacks,” in                    2018, pp. 49–60.
     The Twelfth International Conference on Learning Representations, Oct. [83] T. Wolf, L. Debut, V. Sanh, J. Chaumond, C. Delangue, A. Moi, P. Cistac,
     2023.                                                                                  T. Rault, R. Louf, M. Funtowicz, J. Davison, S. Shleifer, P. von Platen,
[67] S. Pinto and N. Santos, “Demystifying Arm TrustZone: A Comprehensive                   C. Ma, Y. Jernite, J. Plu, C. Xu, T. L. Scao, S. Gugger, M. Drame,
     Survey,” ACM Computing Surveys, vol. 51, no. 6, pp. 130:1–130:36, Jan.                 Q. Lhoest, and A. M. Rush, “Transformers: State-of-the-art natural
     2019.                                                                                  language processing,” in Proceedings of the 2020 Conference on Empirical
     Methods in Natural Language Processing: System Demonstrations. Online:
     Association for Computational Linguistics, Oct. 2020, pp. 38–45.
[84] A. Wood, K. Najarian, and D. Kahrobaei, “Homomorphic Encryption for
     Machine Learning in Medicine and Bioinformatics,” ACM Computing
     Surveys, vol. 53, no. 4, pp. 70:1–70:35, Aug. 2020.
[85] S. Wu, H. Fei, L. Qu, W. Ji, and T.-S. Chua, “NExT-GPT: Any-to-Any
     Multimodal LLM,” Sep. 2023.
[86] S. Wu, O. Irsoy, S. Lu, V. Dabravolski, M. Dredze, S. Gehrmann,
     P. Kambadur, D. Rosenberg, and G. Mann, “BloombergGPT: A Large
     Language Model for Finance,” Dec. 2023.
[87] M. Xue, Z. Wu, C. He, J. Wang, and W. Liu, “Active DNN IP Protection:
     A Novel User Fingerprint Management and DNN Authorization Control
     Technique,” in 2020 IEEE 19th International Conference on Trust, Security
     and Privacy in Computing and Communications (TrustCom), Dec. 2020,
     pp. 975–982.
[88] M. Xue, Y. Zhang, J. Wang, and W. Liu, “Intellectual Property Protection
     for Deep Learning Models: Taxonomy, Methods, Attacks, and Evalu-
     ations,” IEEE Transactions on Artificial Intelligence, vol. 3, no. 06, pp.
     908–923, Dec. 2022.
[89] Y. Yang, M. Sonji, and A. Jog, “Dissecting Performance Overheads
     of Confidential Computing on GPU-based Systems,” in 2025 IEEE
     International Symposium on Performance Analysis of Systems and Software
     (ISPASS), May 2025, pp. 1–16.
[90] C. Zhao, D. Saifuding, H. Tian, Y. Zhang, and C. Xing, “On the
     Performance of Intel SGX,” in 2016 13th Web Information Systems and
     Applications Conference (WISA), Sep. 2016, pp. 184–187.
[91] W. X. Zhao, K. Zhou, J. Li, T. Tang, X. Wang, Y. Hou, Y. Min, B. Zhang,
     J. Zhang, Z. Dong, Y. Du, C. Yang, Y. Chen, Z. Chen, J. Jiang, R. Ren,
     Y. Li, X. Tang, Z. Liu, P. Liu, J.-Y. Nie, and J.-R. Wen, “A Survey of
     Large Language Models,” Nov. 2023.
