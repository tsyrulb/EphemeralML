                                                    Confidential Prompting: Privacy-preserving LLM Inference on Cloud

                                                                                  Caihua Li* , In Gim* , Lin Zhong
                                                                                   Department of Computer Science
                                                                                           Yale University
                                                                          {caihua.li, in.gim, lin.zhong}@yale.edu
                                                                                  *
                                                                                    Both authors contributed equally
arXiv:2409.19134v5 [cs.CR] 19 Nov 2025




                                         Abstract—This paper introduces a vision of confidential prompt-      design secures user prompt confidentiality from adversaries
                                         ing: securing user prompts from an untrusted, cloud-hosted           in the cloud, including the cloud provider and the LLM
                                         large language model (LLM) while preserving model confiden-          provider, while achieving three additional crucial goals for
                                         tiality, output invariance, and compute efficiency. As a first       commercial deployment:
                                         step toward this vision, we present Petridish, a system built        • Model confidentiality prevents LLM parameter leakage to
                                         on top of confidential computing and its core contribution,             users or the cloud provider;
                                         a novel technology called Secure Partitioned Decoding (SPD).         • Output invariance guarantees that the LLM responses
                                         Petridish runs the LLM service inside a confidential virtual            remain the same regardless of whether security measures
                                         machine (CVM), which protects the secrets, i.e., the LLM                are applied or not;
                                         parameters and user prompts, from adversaries outside the            • Compute efficiency requires that the applied security mea-
                                         CVM. Importantly, it splits the LLM service for a user into             sures do not significantly increase the LLM serving cost.
                                         two processes, using SPD: a per-user process performs prefill        Details of our threat model and design goals are in §3.
                                         with the user prompts and computes attention scores during                As outlined in §8, none of existing solutions achieve all
                                         decoding; a service process, shared by all users, batches the        of our goals under the assumption of an untrusted LLM. For
                                         attention scores from per-user processes and generates output        example, techniques like edge inference [2] protect prompts
                                         tokens for all users. Both the LLM provider and the users trust      by processing them locally. However, these techniques do
                                         Petridish’s CVM and its operating system, which guarantees           not work for cloud-hosted large models. They also require
                                         isolation between processes and limits their outbound network        sharing model parameters with users, breaching model
                                         capabilities to control information flow. The CVM’s attestation      confidentiality. Differentially private in-context learning [3],
                                         capability and its open-source software stack enable Petridish       [4] and data anonymization [5], [6], [7], [8] reduce fidelity,
                                         to provide auditable protection of both user prompt and LLM          violating output invariance. Although fully homomorphic
                                         confidentiality. Together, Petridish maintains full utility of LLM   encryption [9], [10] preserves model confidentiality and
                                         service and enables practical, privacy-preserving cloud-hosted       output invariance, its computational overhead is prohibitive
                                         LLM inference for sensitive applications, such as processing
                                                                                                              for practical LLM serving. With confidential computing, a
                                         personal data, clinical records, and financial documents.
                                                                                                              user can protect its prompts from an untrusted LLM provider
                                                                                                              by deploying the LLM service in its owned CVM, at the
                                                                                                              cost of compromising model confidentiality and compute
                                         1. Introduction                                                      efficiency.
                                                                                                                   This paper presents a new approach to confidential
                                         To use today’s cloud-hosted large language model (LLM)               prompting, which enables efficient and scalable LLM serving
                                         services, a user risks exposing private information in prompts       within a CVM, without requiring complete trust in the
                                         to adversaries in the cloud, including the cloud provider and        LLM provider, as illustrated in Figure 1. Our key insight is
                                         the LLM provider. Confidential computing (CC) [1] has                that LLM inference involves two distinct phases: prefill and
                                         emerged as a promising solution to protect user information          decode (§2.1), where the token generation in the decode
                                         from the cloud provider. With CC, an LLM service can run             phase can be formulated as a secure partitioned computation.
                                         inside a confidential virtual machine (CVM), hidden from the              Our system, called Petridish1 , performs the prefill phase
                                         cloud provider. However, it does not protect user information        with user prompts in per-user processes and keeps the
                                         from the LLM provider because the LLM service receives
                                         prompts in plaintext.                                                   1. We name Petridish after “Petri dish”, a transparent lidded dish to hold
                                             This paper solves this problem with confidential prompt-         growth medium for culturing cells [11]. Both our CVM and the Petri dish
                                         ing. We assume that users and the LLM provider are mu-               isolate their inner environment from the outer. Our CVM is “transparent”
                                                                                                              for users and LLM provider to audit its open-source software stack and to
                                         tually untrusted, while neither trusts the cloud provider.           verify if the environment is integral. In analogy to cells, processes interact
                                         Each party seeks to uncover the other’s secrets, namely user         with each other but are isolated in overall. The trusted OS protects the
                                         prompts and LLM parameters. Under this assumption, our               process execution, analogous to how the growth medium supports the cells.
               LLM
 LLM     Parameters                                    LLM Parameters                            Service
 Provider                                                                                        Process                Trusted Execution
                                     Process C                        Input KV cache       Q                            Foundation
            Prompt C                                        Prefill
 User C                                          Prompt C                                  Ain
           Output C      Process
                        Controller                          Output C
                                                                                                                        Processes
            Prompt B                                                                                         Batch
 User B                                                                                                    Processed
           Output B                  Process B
          Challenge                                         Output B                                                    Open-source
 User A                                                                                          Output KV cache        Software Stack
          Attestation
            Report
                                                                Trusted OS
 Adversaries
                                                                                                                        Data transfer
  illegal access
                                                                      CVM                                               or access

Figure 1: Petridish Overview. Both users and the LLM provider audit the open-source software stack (colored in grey) and
verify the execution environment (e.g., challenge performed by User A) before transmitting any secrets via secure encrypted
channels. The Process Controller initializes a dedicated process for each user and the LLM provider, which executes within
the CVM and on top of the trusted OS. The CVM prevents illegal access from outside the CVM, while the trusted OS
guarantees isolation between processes. The per-user processes separately prepare their own input KV cache during prefill,
and interact with the service process to generate output tokens using SPD. After decoding, the Process Controller relays
output tokens from the service process to the corresponding users.


resulting KV attention states within these per-user processes.              be reversed to the prompts because attention computation
We refer to these KV attention states as the input KV cache                 involves complex, many-to-one transformations that lose
because they are derived from the user input prompts and                    information about the original input [12], [13]. As for the
must be kept confidential from the service process. Petridish               latter, a recent work by Tan et al. [14] provides strong
then performs decode mostly in the service process, without                 empirical evidence that SPD is secure. Tan et al. [14] tests
knowing the user prompts or the input KV cache, using a                     state-of-the-art prompt stealing attacks [15], [16], [17] on
technique called Secure Partitioned Decoding (SPD). During                  in-the-wild prompts and responses, concluding that existing
decode, the service process generates output tokens and                     prompt stealing attacks achieve low prompt recovery rates
computes associated KV attention states, which we refer to                  from the output tokens in practice (§2.4.3). Detailed security
as the output KV cache because they are derived from the                    analysis of SPD is in §4.3.
generated output tokens. See §4 for the detailed design.                        Beyond user prompt confidentiality, our SPD design is
    SPD formulates token generation in the decode phase as                  also computationally efficient and lossless in output fidelity.
a secure partitioned computation, where one participant is a                First, SPD is efficient because (i) the service process can
per-user process and the other is the service process. In other             batch and parallelize computations over output KV cache and
words, we partition the full attention score computation into               attention scores for all users, and (ii) the per-user processes
two parts: the input attention score Ain and the output                     do not retain their own copy of LLM parameters, thereby
attention score Aout , computed by the two processes with the               maintaining a small footprint. Second, SPD ensures that the
input KV cache and the output KV cache respectively. To be                  LLM responses remain unchanged as the attention score
more precise, the per-user process uses the precomputed                     decomposition is lossless. Please refer to §4.2 for details.
input KV cache to compute input attention score Ain ,                           To achieve all of our goals, SPD must collaborate with
without requiring the LLM parameters and thus reducing the                  the CVM and its guest software stack, which together form
memory footprint during decode. Then it sends Ain to the                    the Petridish as an integrated system. First, SPD relies on
service process. Meanwhile, the service process computes                    the underlying trusted OS to guarantee process isolation,
the output attention score Aout with the output KV cache                    protecting every processes from unauthorized access. Second,
of the preceding output tokens. Then it merges Aout with                    to maintain model confidentiality, Petridish introduces a
Ain received from the per-user process for the next token                   Process Controller, which works with the trusted OS to
generation, and maintains output KV cache accordingly.                      restrict outbound network access from per-user processes,
    Our SPD design secures user prompt confidentiality since                preventing LLM parameter exfiltration (See §4.1 for details).
the user prompts and input KV cache remain confidential                     Finally, all guest software and data rely on the CVM to ensure
within the per-user processes. Neither the LLM provider                     their integrity and confidentiality, preventing any adversaries
nor the cloud provider can access user prompts. The service                 in the cloud from tampering with or stealing secrets in the
process learns only the received input attention score Ain                  CVM. In a nutshell, Petridish effectively safeguards both
and the generated output tokens. The former typically cannot                user prompt and LLM confidentiality by enforcing strict


                                                                       2
memory isolation and information flow control.                            the softmax function. The output becomes an input to the
     Petridish’s design ensures no party has more privileges              next layer. When the final layer is reached, the LLM samples
in the CVM than the others, preventing any party from                     the next token xn+1 from the distribution and appends it
compromising Petridish’s guarantees. In other words, neither              to the token sequence, iteratively until some termination
the LLM provider nor the users have administrative access                 condition is met, so-called autoregressive token generation.
to Petridish’s CVM. Specifically, Petridish always uses an
open-source software stack, either by open-sourcing its own               2.1.2. KV Cache. The KV cache mechanism [23], [24],
implementation such as the Process Controller or by lever-                [25], [26] is a common optimization used to improve LLM
aging existing open-source software such as Linux, allowing               inference efficiency. This mechanism leverages the causal
users and the LLM provider to audit the software. All parties             nature of LLMs: when predicting token xi in a sequence, the
can perform remote attestation to verify the integrity of the             attention calculation only considers its preceding tokens,
CVM environment, ensuring its executing software stack                    x1 , . . . , xi−1 , rather than any tokens that follow. Conse-
matches the open-source one. So, unlike traditional CVMs,                 quently, instead of recalculating attention for all tokens at
Petridish’s CVM does not have an administrative owner and                 each token generation, the LLM inference engine caches
its initialization does not rely on a trusted party either. This          previously calculated attention states and reuses them for
design establishes trust between Petridish with both users                subsequent inferences. Because the reusable attention states
and the LLM provider by ensuring auditability of the CVM                  are the K and V matrices for each token, this cache is called
and its software stack. Please refer to §3.3 for details.                 the KV cache.
     In §5, we report an implementation of Petridish. In §6,
we evaluate our prototype on an Nvidia H100 GPU with CC                   2.1.3. Prefill and Decode. Applying KV cache naturally
enabled, comparing Petridish with two existing confidential               separates the LLM inference process into two distinct stages:
inference approaches (§2.3). We show that Petridish scales                prefill and decode. The LLM inference process begins with
well to the number of concurrent requests and achieves                    the prefill phase (or prompt processing), where the model
5× better latency than the existing CVM-based approach                    processes all tokens in the input prompt. This phase is
against an untrusted LLM. In §7, we discuss how Petridish                 responsible for calculating the initial K and V matrices
incorporates with orthogonal defenses to mitigate attacks out             for the entire prompt, thereby initializing the KV cache and
of our threat model, as well as its portability and limitations.          generating the first output token after processing the prompt.
We conclude our work in §9, believing that cloud-hosted                   The subsequent decode phase (or token generation) is
LLM service that is both privacy-preserving and efficient is              responsible for the token-by-token autoregressive generation
important and timely. Our work marks the first step towards               of the LLM response. At each token generation, only the K
utilizing confidential computing for privacy-preserving LLM               and V matrices for the newly generated token are calculated
serving, and we hope it will spark further discussion on                  and appended to the existing KV cache.
confidential prompting.
                                                                          2.2. Confidential Computing (CC)
2. Background
                                                                          Confidential computing protects data in use, complementing
We next provide a succinct background of related techniques.              traditional security measures such as encryption that protect
Specifically, we review existing confidential inference ap-               data at rest and data in transit. The most common approach
proaches, with or without trust on the LLM provider, and                  to confidential computing is using trusted execution environ-
discuss their limitations in §2.3. We also review the major               ments (TEEs), i.e., enclaves and confidential virtual machines
threats we aim to defend against and the state-of-the-art                 (CVMs), which are provided by hardware features such as
prompt leakage attacks in §2.4.                                           Intel SGX [27], AMD SEV-SNP [28], and ARM CCA [29].
                                                                              The TEEs isolate sensitive code and data from the rest
2.1. LLM Inference with KV cache                                          of the system. Thanks to their strong isolation capabilities,
                                                                          hardware-based TEEs guarantee that even privileged software
2.1.1. LLM Inference. We consider GPT-style LLMs [18],                    such as the operating system (OS) and the hypervisor cannot
[19], [20], [21], which are trained to predict the distribution of        access the sensitive data being processed. In addition to
the next token, xn+1 , given a sequence of tokens x1 , . . . , xn ,       isolation, most hardware-based TEEs also provide memory
known as causal language modeling. This prediction process                encryption and remote attestation. Memory encryption guar-
uses the Transformer architecture [22], which consists of                 antees all code and data in TEE memory are encrypted,
multiple self-attention layers. For a sequence of length                  offering an additional layer of protection against physical
n, represented as X ∈ Rn×d , the Transformer produces                     attacks such as cold boot attacks. Remote attestation al-
an output sequence Y ∈ Rn×d , where d is the hidden                       lows users to verify the integrity of a remote TEE, before
dimension size. The self-attention mechanism involves five                transmitting any sensitive user data.
matrix multiplications. First, the model calculates matrices
Q = XWQ , K = XWK , and V = XWV , where WQ , WK ,                         2.2.1. Remote Attestation in LLMaaS Scenario. It is worth
and WV ∈ Rd×d are trainable weight matrices. Next, the                    noting that the users who remotely verify a TEE are not
output is calculated as Y = σ(QK ⊤ )V , where σ(·) denotes                necessarily the same entity that instantiated the TEE. A


                                                                      3
typical example is the LLM as a service (LLMaaS) scenario,           2.3. Confidential Inference
where a LLM provider deploys the LLM within a CVM to
serve multiple users (Figure 2a). Users must independently           Figure 2a illustrates the standard confidential inference
verify the integrity of the environment running the LLM,             approach, where the LLM provider instantiates a CVM
even though they did not create or control the underlying            and deploys the LLM service within it to serve multiple
CVM. That is, before prompt submissions, users request               users. This approach is commonly adopted by many exist-
attestation reports from the CVM remotely and verify if the          ing commercial services, such as confidential inference in
measured hash value in the reports matches the expected              Azure [36]. It can effectively defend against adversaries in the
baseline value provided by the LLM provider. This process            cloud, including the cloud provider. However, this approach
tells whether the CVM is running the expected software               requires all users to fully trust the LLM provider, as the
stack as claimed by the LLM provider.                                LLM provider controls the CVM environment and is able
                                                                     to access user prompts in plaintext. Such trust is necessary
                                                                     because a malicious LLM provider can also leak user secrets
                                                                     by leaving backdoors in the LLM software. Beyond the
2.2.2. Auditing Code Enables Zero Trust on CVM Owner.                LLM provider, users must also trust that the LLM software
In traditional remote attestation process as described above         will not be compromised; for instance, vulnerabilities in the
(§2.2.1), users must trust the LLM provider, who, as the CVM         LLM software could be exploited by a malicious user to leak
owner, provides the image for instantiating the CVM. This            sensitive information in other users’ prompts [37]. Please
trust is necessary when the source code of the CVM image is          refer to §2.4 for example attacks.
not provided, because remote attestation can only verify the             Figure 2b illustrates an alternative approach that each
integrity of the software running inside the CVM, but cannot         user instantiates a dedicated LLM service within its own
guarantee the absence of malicious code or vulnerabilities           CVM. This approach offers strong security guarantees for
within the software itself.                                          users since the users have full control over their CVM
    However, users are not necessary to trust the CVM owner          environments, ensuring that no other users or the LLM
if the source code of the CVM image is open to users,                provider can access their prompts. However, this approach
which allows the users to audit the code for any potential           requires sharing parameters with users and suffers from three
backdoors and vulnerabilities. In practice, after auditing the       significant inefficiencies: (i) low throughput due to reduced
source code, users can independently build the CVM image             batch parallelism, (ii) limited scalability as the number of
from the source code, and verify if the hash value of the            concurrent LLM instances is constrained, and (iii) per-user
built image matches the expected baseline value provided             CVMs are not commercially viable for individual users. For
by the CVM owner. This approach is already adopted by                example, a LLM with 13B parameters requires about 26 GB
some open-source confidential computing projects, such as            of memory for its parameters using 16-bit floating point,
Tinfoil [30], [31], [32]. However, these projects require all        which means that an 80 GB H100 GPU can support up to
software components in the CVM image to be open-source,              three LLM instances that execute simultaneously. Moreover,
which may not be feasible for commercial LLM providers.              inference is performed independently for each of m users,
                                                                     e.g., X1 W, · · · , Xm W , which is less efficient than batching
                                                                     as (X1 : · · · : Xm )W .
                                                                         If all users and the LLM provider achieve a consensus
2.2.3. GPU Confidential Computing (GPU CC). Nvidia                   that a trusted OS can safeguard both user prompts and
introduces GPU CC in its latest architectures such as Hopper         LLM parameters (See §3.3 for a reference design), then
and Blackwell, extending the CVM protection domain to                an improved setup can be adopted as depicted in Figure 2c.
include both CPU and GPU [33]. Nvidia GPU CC guarantees              In this setup, each user owns a separate process running
strong isolation for GPU computation and supports remote             a dedicated LLM instance while sharing a single CVM.
attestation. However, unlike CPU-based TEE, it does not              This approach offers the same level of security as the
support memory encryption for data in GPU memory. Instead,           per-user CVM approach (Figure 2b), because the isolation
end-to-end encryption for data transfers between the host and        between per-user processes is guaranteed by the trusted
GPU devices is managed collaboratively by the GPU driver             OS instead of the LLM software. Compared to the per-
and the devices. Taking Nvidia H100 GPU as an example, the           user CVM approach, this approach retains LLM parameter
CPU and GPU do not share a hardware encryption key, and              confidentiality, and is more affordable because all users share
the GPU devices are blocked from directly accessing CPU-             a single CVM. However, it still suffers from the other two
based TEE memory. As a result, all communication between             inefficiency problems: (i) low throughput due to reduced
the host and the devices must go through a bounce buffer             batch parallelism, (ii) limited scalability as the number of
allocated in non-TEE memory. Consequently, all transferred           concurrent LLM instances is constrained.
data requires an additional copy through the bounce buffer,              Our design, SPD, takes a step forward to address both
along with redundant encryption and decryption operations            inefficiency problems by isolating user prompts in the per-
to ensure security [34]. Such overhead is unavoidable until          user processes while sharing the same LLM instance across
Nvidia provides more hardware support such as TEE-IO in              all users (Figure 2d). SPD’s goal is not to replace existing
its later architectures like Blackwell [35].                         solutions, but to offer an alternative approach for different


                                                                 4
             CVM                                                                     CVM                                  CVM
                   LLM Process                                           Process A         Process B                             LLM Process
         KV cache
  User A                                                                                                Process A
  User B                                                                         Process C              Process B
  User C                                                                                                Process C
       prompt output   LLM                                                                                          Private KV   Public KV

  (a) LLM Provider’s CVM             (b) Per-user CVMs               (c) Per-user Processes in a CVM (d) Secure Partitioned Decoding
Figure 2: Various confidential inference approaches. (a) LLM provider deploys a LLM service in its CVM to serve
multiple users, which defends against adversaries outside the CVM, but the LLM provider still gets user prompts in plaintext.
(b) Each user deploys a dedicated LLM service in its own CVM, which secures user prompts but not LLM parameters, and
is inefficient due to lack of batch parallelism and large memory footprint. (c) In an auditable trustworthy CVM, each per-user
process runs a dedicated LLM service. This approach secures both user prompts and LLM parameters, but is still inefficient
due to lack of batch parallelism and large memory footprint. (d) SPD strikes a balance between security and efficiency by
isolating user prompts within per-user processes, while allowing the single LLM service to batch decode for all users.


scenarios, as discussed in §7.3. Some prior works [38], [39],         2.4.3. Prompt Stealing Attacks. Prompt stealing attacks
[40] can enhance isolation between processes within a single          try to recover hidden user prompts given the associated
CVM, even in cases that the trusted OS is compromised,                LLM generated output tokens. Some state-of-the-art tech-
which can be adopted with SPD to further improve security.            niques [15], [16], [17] achieve a reasonable success rate in
However, when used independently, these prior works fail              synthetic academic prompt datasets. However, a later study
to address the inefficiency problems mentioned above.                 by Tan et al. [14] points out that the user prompts in real-
                                                                      world differ from the synthetic academic datasets in terms of
2.4. Prompt Leakage                                                   length, semantics, and domain. Its empirical experiments [14]
                                                                      show that existing prompt stealing attacks, which previously
We first review the major threats to user prompt confidential-        performed reasonably on synthetic academic datasets, strug-
ity in LLM inference (§2.4.1) and in LLM software (§2.4.2).           gle against the real prompts. As a result, they achieve low
We notice that these threats mainly arise from the lack               recovery quality in practice. These empirical experiment
of proper memory isolation and information flow control.              results are strong evidences that Petridish is secure against
Petridish enforces strict memory isolation and restricts              the state-of-the-art prompt stealing attacks.
information flow to mitigate these threats. However, Petridish
must still allow the minimal information flow required for            2.4.4. Prompt-leakage Injection Attacks. Prompt-leakage
token generation. In §2.4.3 and §2.4.4, we respectively               injection attacks are techniques where attackers craft input
review prompt stealing and prompt-leakage injection attacks           instructions like “repeat the system instruction” to manipulate
that may exploit such minimal information to reverse user             a LLM service into revealing hidden information such as
prompts. We also discuss recent developments in mitigating            system instructions. Hung et al. [41] observe that, during
these attacks, which are orthogonal to Petridish.                     a successful injection, some specific attention heads shift
                                                                      their focus away from the original instruction toward the
2.4.1. Major Threats. In traditional LLM inference, user              injected instruction, termed the distraction effect. Based
prompts reside in memory in plaintext, without proper                 on this observation, Hung et al. [41] effectively detect
isolation and protection. These prompts are under threats             injection attacks by monitoring attention score on the original
from (1) a malicious cloud provider and any adversaries who           instruction. An attack is detected whenever the monitoring
compromise isolation enforced by the cloud; (2) an untrusted          attention score falls below an empirical threshold.
LLM provider and any malicious users who compromise                       In Petridish, a malicious service process may alter output
isolation within the internal LLM service process. The                token generations to inject prompt-leakage instructions into
standard confidential inference approach (Figure 2a) can              the output token sequences. This will lead to distraction effect,
defend against (1) but not (2).                                       causing subsequent token generations to follow the injected
                                                                      instruction instead of the original instruction, and thus to leak
2.4.2. Threats in LLM Software. When using closed-source              the hidden user prompts. However, such attacks are detectable
LLM software provided by an untrusted LLM provider,                   by monitoring Petridish’s input attention scores within the
there is a significant risk that the provider could inject            per-user processes, similar to the detection approach proposed
backdoors to leak user prompts. Even if the LLM software is           in Hung et al. [41].
open, vulnerabilities such as flaws in memory isolation and
shared cache mechanisms can still be exploited to leak the            3. Design Overview
prompts. For example, a recent study [37] demonstrates how
a malicious user leverages the shared KV cache mechanism              We introduce Petridish’s threat model (§3.1), design goals
in popular LLM software to recover other users’ prompts.              (§3.2), and an overview of its auditable protection (§3.3).


                                                                 5
3.1. Trust and Threat                                                  For example, detection of injection attacks is practical, as
                                                                       discussed in §2.4.4 and §7.1.
To clarify the threat model, we identify the major parties                 Denial of service (DoS) attacks are out of consideration.
involved in Petridish’s design and their potential interests.          We do not consider attacks that compromise the communica-
We categorize these parties as follows.                                tion channels or the CVM either. In §7.1, we discuss some
• Users, who send prompts to request LLM service, and
                                                                       potential attacks on the TCB and their mitigations.
   may seek to steal LLM parameters and other user prompts.
• LLM provider, who provides LLM parameters and soft-                  3.2. Design Goals
   ware, and may seek to steal user prompts.
• Cloud provider, who provides the cloud infrastructure, and           Our primary goal is to secure user prompt confidentiality
   may seek to steal LLM parameters and user prompts.                  in cloud-hosted LLM service. Beyond the primary goal, we
• CVM hardware and guest software stack providers, such                target three additional goals for commercial deployment.
   as AMD, Nvidia, and Linux, who are trusted by all parties.          • Model confidentiality: LLM parameters must not leak.
It is worth noting that the users do not trust each other, and           This is critical as the parameters constitute an intellectual
thus each user is regarded as a different party.                          property of the LLM. Preserving model confidentiality
                                                                          enhances the deployability of closed-source LLMs.
3.1.1. Trusted Computing Base (TCB). Petridish’s TCB                   • Output invariance: Security measures must not change the

includes CPU and GPU hardware in the cloud, as well                       output of LLM. This is crucial for deployment, particularly
as the open-source CVM guest software stack such as                       for tasks in clinical and financial fields, where even a small
Linux kernel [42], Nvidia Linux GPU driver [43] and                       accuracy error could lead to serious consequences.
                                                                       • Compute efficiency: Security measures cannot signifi-
Petridish’s Process Controller. Specifically, Petridish trusts
the confidential computing extensions, such as AMD SEV-                   cantly increase the LLM serving cost. While security is
SNP [28], ARM CCA [29], and Nvidia GPU CC [33].                           not free, we believe that a more efficient approach is more
     We assume that both users and the LLM provider                       attractive to users.
independently audit the open-source code of the CVM guest
software stack. After auditing, they achieve a consensus on            3.3. Overview of Petridish’s Auditable Protection
its trustworthiness. They also verify the integrity of the CVM
in the cloud via remote attestation before transmitting any            As shown in Figure 1, Petridish’s core components, including
secrets. We assume that the communication channels between             the CVM, the trusted OS, and the Process Controller,
users (as well as the LLM provider) and their associated               integrate as a system and collaborate to provide auditable
processes in the CVM are secure.                                       protection. We next present an overview of this collaboration.
     On the other side, the rest of the cloud infrastructure may       Auditable Software Stack Petridish’s CVM guest software
be compromised (or the cloud provider may be malicious)                stack is open-source for independent audits by users and the
and is therefore out of the TCB.                                       LLM provider, such as the Linux kernel [42], Nvidia Linux
                                                                       GPU driver [43], and the Process Controller. Such audits
3.1.2. Threat Model. Based on our discussion in §2.4, we               are crucial for establishing trust between Petridish with both
summarize our threat model as follows.                                 users and the LLM provider. On one hand, these parties can
• Threat from Cloud: A malicious cloud provider and any                ensure that the software stack is provided by trusted parties
  adversaries that compromise the cloud platform attempt               such as Linux community and Nvidia, instead of the cloud
  to steal user prompts and LLM parameters.                            provider, LLM provider, or any users. On the other hand,
• Threat from LLM: The LLM provider, possibly colluding                by analyzing the processing logic and data flow reflected in
  with some users, attempts to steal user prompts.                     the source code, the participants gain confidence that their
• Threat from Users: A user leverages security holes in                secrets are well protected at runtime. Notably, Petridish does
  LLM software to steal LLM parameters and user prompts.               not require the LLM software or the userspace CUDA
For example, traditional LLM inference is vulnerable to all            drivers to be open source, which distinguishes our approach
three kinds of threats, while standard confidential inference          from related projects such as Tinfoil [30], [31] (See §2.2.2
approach (Figure 2a) is threatened by the LLM and the users.           for more details). At runtime, they execute as unprivileged
    It is worth noting that we assume the LLM provider                 processes in user mode. The trusted OS guarantees that they
behaves rationally, which means it follows the prescribed              cannot harm the rest of the system.
inference steps to maximize its own benefit, although it is            CVM’s Decentralized Initialization As discussed in §2.2.2,
untrusted, curious about user prompts, and even seeking                independent code audits combined with remote attestation
profit from user secrets. This assumption aligns with the              eliminate the need to trust the CVM owner, i.e., the party
Honest-but-Curious (HbC) threat model commonly used in                 who instantiates the CVM in the cloud. Petridish’s design
secure computation literature [44]. HbC model also reflects            and its auditable software stack guarantee that the CVM
industry practice where the LLM provider is incentivized to            owner does not have any higher privilege than other parties.
maintain integrity for reputation, especially when altered to-         As a result, we do not restrict who instantiates the CVM,
ken generations performed by the LLM service are detectable.           which can be the LLM provider, any user, or even any


                                                                   6
third party, as long as all participants verify the integrity                         We first present an overview of the secure partitioned
of the CVM via remote attestation before transmitting their                           computation protocol and then detail each component in
secrets. Such a decentralized feature make Petridish differ                           the following. There are four participants in the protocol:
from the standard confidential inference approach, as shown                           • A user, who sends prompts to request LLM service and
in Figure 2a, which requires a centralized trusted party to                             receives output tokens as responses securely.
play as the CVM owner.                                                                • The user’s process, which represents the user to process

Attestable CVM Environment As mentioned in §2.2, CVM’s                                  the prompts and interacts with the service process.
remote attestation capability allows users and the LLM                                • The service process, which represents the LLM provider

provider to verify if the CVM hardware is genuine and                                   to provide LLM service for users.
                                                                                      • The Process Controller, which initializes processes in
to check if different aspects of the boot process match
with the audited guest software stack. To be more precise,                              the CVM and enforces information flow control policies.
the CVM hardware generates an attestation report, which                               We next introduce the computation and communication
encapsulates the measurement, i.e., cryptographic hash, of                            protocol among these four participants.
different aspects of the boot process. Since the software stack                       1) Setup (§4.1): The Process Controller initializes processes
is open-source, all parties can independently compute the                                for the user and the LLM provider, respectively, in the
expected measurement value and compare them with those                                   CVM. It establishes secure channels with the user and
in the attestation report. As a result, they can ensure that the                         the LLM provider, while restricting network access for
CVM is untampered prior to secret transmission.                                          their processes. Both the user and the LLM provider send
Runtime Enforcement Auditing source code and verifying                                   their secrets, i.e., user prompts and LLM parameters, to
CVM integrity at initialization are necessary for establishing                           the Process Controller over the secure channels, which
trust. However, these measures alone are not sufficient                                  then relays them to the associated processes.
to prevent information leakage at runtime. The key lies                               2) Prefill (§4.1): The per-user process computes input KV
in the collaboration between the CVM, the trusted OS,                                    cache Kin , Vin and generates the first token. It then sends
and the Process Controller to enforce runtime protection,                                the first token to the service process.
which includes cryptographically protected communication,                             3) Decode (§4.2): Receiving the first token from the per-user
sensitive data isolation, and information flow control. We                               process as a new token, the service process generate the
elaborate on these mechanisms in §4.                                                     next token autoregressively. As depicted in Figure 3, for
                                                                                         each transformer layer:
4. Efficient Protection of Prompt and LLM                                                a) The service process computes QNew , KNew , VNew of
                                                                                             the new token, sends QNew to the per-user process, and
As discussed in §2.3, under the assumption of an untrusted                                   appends KNew , VNew to output KV cache Kout , Vout .
LLM provider, it is difficult to balance efficiency with                                 b) The per-user process responds with input attention
                                                                                                                         ⊤
confidentiality of both user prompts and LLM parameters.                                     score Ain = σ(QNew Kin        )Vin .
That is, assigning a dedicated LLM service for each user                                 c) The service process computes output attention score
                                                                                                                  ⊤
unavoidably leads to significant inefficiency, although it                                   Aout = σ(QNew Kout       )Vout , and merges it with Ain to
allows explicit isolation between user prompts (Figure 2b,                                   get full attention score Y = σ(QNew K ⊤ )V according
Figure 2c). Petridish overcomes this challenge by enforcing                                  to Theorem 1.
strict data isolation and flow control over user prompts and                             d) If it is the final layer, the service process samples a new
LLM parameters, while enabling efficient batch processing                                    token from Y , sends it to the Process Controller, and
across all user prompts by a single LLM service (Figure 2d).                                 continues generating tokens until [EOS]. Otherwise,
     Our key insight is that the token generation can be                                     it continues to the next layer.
formulated as a secure partitioned computation between the                            4) Response (§4.1): The Process Controller collects all
users and the LLM provider. Each user owns a process within                              generated output tokens from the service process and
Petridish’s CVM and each of these processes represents the                               sends them to the user via the secure channel.
associated user as one participant in the secure partitioned                          This protocol can be generalized to scenarios with multiple
computation. Petridish partitions the KV cache into input                             users, each with its own process operating in the CVM.
KV cache and output KV cache, which are associated with
the user input prompts and LLM generated output tokens                                4.1. Data Isolation and Flow Control
respectively. The input KV cache of user prompts is private
and kept confidential in the per-user processes, while the                            As analyzed in §2.4, the key to preserving confidentiality of
output KV cache is processed by the LLM service process.                              user prompts and LLM parameters lies in explicit memory
     For simplicity, we detail our design in a single-user                            isolation and strict information flow control. The Process
scenario 2 , assuming that the CVM and its guest software                             Controller and the underlying trusted OS collaborate to
stack have been audited, initialized, and verified (§3.3).                            enforce the isolation and flow control policy.
   2. The extension from single-user to multi-user scenario is trivial, because
the computation in a per-user process is independent on other users, and              4.1.1. Secure Channel and Process Initialization. Once
the LLM service process can batch process for all users.                              Petridish’s CVM is initialized, the Process Controller keeps


                                                                                  7
listening on connections from users and the LLM provider.             User A’s process
                                                                                         0                               6
During each connection setup, the Process Controller and                   First token                         Next token             Service
                                                                           generation          MLP
the user (or the LLM provider) use Diffie-Hellman key                                                          generation             process
                                                                                4                  5           3                  1
exchange protocol [45] to jointly derive unique symmetric
                                                                            σ(QKin)Vin       Theorem 1    σ(QKout)Vout       QKV projection
keys for secure communication. In other words, a secure
                                                                                   Qnew                    Qnew
channel is established between the Process Controller and                                                                                Xnew
                                                                               KVin                                KVout         KVnew
the user (or the LLM provider). The Process Controller                                                                       2

then creates a dedicated process for the user (or the LLM                                                                                  new
provider). Specifically, the Process Controller sends the             User B’s process                                                    token
symmetric keys to the created per-user process via Inter-
process Communication (IPC). It implies that the users can
securely submit prompts to their associated processes, where          Figure 3: Overview of SPD on a simplified Transformer
the Process Controller acts as a relay.                               layer. The squares in blue and red represent the KV cache
                                                                      associated with different users while the gray squares rep-
                                                                      resent new tokens. With or without shade indicate it is the
4.1.2. LLM Parameter Read-only Sharing. After the                     output or input KV cache, respectively. ⃝     0 By the end of
secure channel is established, the LLM provider securely              prefill, the user process finishs computing its input KV cache
transmits the LLM parameters to the Process Controller,               Kin , Vin , generates the first token and sends it to the service
which then saves the parameters as a read-only file in the            process. ⃝   1 Project hidden state Xnew of a new token to
CVM memory and grants read-only access permission to both             Qnew , Knew , Vnew . ⃝
                                                                                           2 Append Knew , Vnew to the output KV
the service process and all per-user processes. As the file is        cache. ⃝  3 Batch process output attention score for all users.
read-only, these processes can safely share the same copy of          ⃝4 Compute input attention score in each user process. ⃝        5
the LLM parameters without risking malicious modification.            Merge results to compute full attention score. ⃝    6 If it is the
It is worth noting that, each per-user process accesses the           last layer, generate the next token, then repeat from ⃝   1 until
LLM parameters only during the prefill phase to compute               finish; otherwise continue to the next layer.
the input KV cache. In addition, all per-user processes can
leverage CUDA IPC [46] to share GPU memory for the
LLM parameters, so to avoid redundant parameter loading               input and output tokens, and σ be the softmax function.
and GPU memory consumption.                                                                        γin
                                                                                σ(QK ⊤ )V =               σ(QKin⊤
                                                                                                                  )Vin
                                                                                               γin + γout
                                                                                               γout          ⊤
4.1.3. Restricted Network Access. To prevent the per-                                     +            σ(QKout  )Vout ,       (1)
                                                                                            γin + γout
user processes from leaking LLM parameters, the Process
Controller leverages Linux namespaces to restrict their               where γin , P
                                                                                  γout are denominators of each softmax operation,
                                                                                             ⊤
network access capabilities. Specifically, at process creation,       e.g. γin = exp(QKin      ).
the Process Controller configures each per-user process to                The proof of Theorem 1 is available in §A. This theorem
operate within a dedicated and isolated network namespace.            serves as the foundation of our SPD design, which offers
As a result, each per-user process can communicate with its           three key benefits. First, the decomposition is lossless and
associated user only under the inspection from the Process            thus SPD maintains output invariance. Second, computations
Controller, which acts as a relay in the communication. For           in per-user processes do not require LLM parameters during
example, the users send encrypted prompts to the Process              decode, which means the per-user processes only require a
Controller, which then forwards them to the associated per-           small amount of memory for the input KV cache and input
user processes via IPC. On the other hand, the Process                attention states. Third, the LLM service process can batch
Controller collects the generated output tokens accordingly           process the output attention states (Q, Kout , Vout ) for all
and sends them back to the associated users.                          users in parallel.
                                                                          We can naturally extend Theorem 1 to the multi-user
                                                                      scenario. When multiple requests from different users arrive
4.2. Secure Partitioned Decoding (SPD)                                simultaneously, each per-user process computes its own input
                                                                      attention score independently, while the service process batch
We formulate the decoding in the single-user scenario as              processes the output attention states for all users in parallel.
a secure partitioned computation using the online softmax             This enables efficient and isolated computation for multiple
calculation [47]. This secure computation enables the LLM             users, especially when the NVIDIA Multi-Process Service
to retrieve the full attention score Y without knowing the            (MPS) is enabled [48], which allows multiple processes
user prompt and the input KV cache Kin , Vin .                        to concurrently and spatially share GPU resources while
                                                                      maintaining isolation on GPU devices.
Theorem 1 (Secure Partitioned Attention Computation).                     Finally, it is worth noting that computing γin and γout
Let Q ∈ Rd , K = concat(Kin , Kout ) ∈ Rlen×d , V =                   individually is numerically unstable due to their exponential
concat(Vin , Vout ) ∈ Rlen×d , where len be the number of             term. To address this, we use the maximum values for input


                                                                  8
and output attention scores, denoted as min and mout , respec-          send any data out of the CVM, as enforced by network
tively, to improve numerical stability. In practice, we optimize        namespace restrictions managed by the Process Controller.
                                             ⊤
                               P
the computation as γin =          expP  (QKin   − min ), where          As a result, the LLM secrets are secure although the per-user
                   ⊤                                ⊤
min = max(QKin ), and γout =              exp(QKout    − mout ),        processes have read-only access to them during prefill. It is
                          ⊤
where mout = max(QKout       ). The coefficients in Theorem 1           worth highlighting that the output tokens generated by the
become γin /(γin + αγout ) and γout /(α−1 γin + γout ), where           service process are sent to the user by the Process Controller
α = exp(mout − min ).                                                   instead of the per-user processes. This explicit separation
                                                                        ensures that per-user processes cannot exfiltrate model data
4.3. Security and Functional Analysis                                   via output tokens, as all output delivery is strictly controlled
                                                                        by the Process Controller.
User Prompt Confidentiality We analyze how Petridish pro-               Compute Efficiency Petridish’s SPD design enables effi-
tects user prompt confidentiality against the threats outlined          cient computation by allowing the service process to batch
in §2.4 and §3.1.                                                       process output attention states for all users in parallel.
    First, user prompts remain confidential from adversaries            This increases GPU utilization substantially. In contrast,
on the cloud, including the cloud provider. The prompts are             confidential inference approaches that assign a dedicated
encrypted during transmission and will not be decrypted                 LLM service for each user cannot leverage batch processing
until they are in the CVM, which provides strong isolation              across users (See §2.3 for details). In addition, Petridish’s
and its integrity is verified via remote attestation.                   auditable CVM environment (§3.3) allows secure software-
    Second, the service process cannot access user prompts              level optimizations, such as read-only data sharing and
as the prompts and their input KV cache remain confidential             enabling Nvidia MPS [48], while eliminating the need of a
within per-user processes. The trusted guest OS guarantees              centralized trusted party to play as the CVM owner.
isolation among processes to avoid any secret exposure.                 Output Invariance Petridish’s SPD design maintains output
The service process learns only (1) the generated output                invariance by ensuring the attention computation is mathemat-
tokens, and (2) the input attention score Ain . However, it is          ically equivalent to the original token generation process, as
not practical for an attacker to recover user prompts from              demonstrated in Theorem 1. Petridish does not introduce any
such information. For (1), the state-of-the-art techniques for          approximation or require LLM retraining, thus preserving
recovering prompts from LLM output [15], [16], [17] have                the invariance of the output tokens, which distinguishes our
been proven to perform poorly on in-the-wild prompts in                 approach from the related work (See §8 for details).
practice [14] (See §2.4.3 for details). For (2), the attention
score computation is an information-losing map, meaning that
it discards much of the original information of the prompt
                                                                        5. Implementation
and retains only those relevant for generating the output
token, as suggested by its term “attention”. As a result, the           We next describe key implementation details of Petridish.
input attention score Ain is typically irreversible to the user         Auditable Software Stack Petridish’s software stack is
prompt, unless the query matrix Q is adversarially selected.            available in GitHub, allowing users and the LLM provider
This implies that a more promising attack is to inject prompt-          to audit the code for any potential backdoors and vulnerabil-
leakage instructions, which induce the input attention score to         ities. It includes the Linux kernel [42], Nvidia Linux GPU
keep as much information about the prompt as possible, and              driver [43], PyTorch [49], attestation tools [50], [51], [52],
further induce prompt leakage in token generation. However,             and the Process Controller. One can leverage the GitHub
such an attack would require the LLM service to manipulate              Actions CI/CD pipeline to automatically build the CVM
the inference process, which falls outside our Honest-but-              image from the source code [53]. The pipeline can also
Curious threat model and is detectable by existing work [41]            generate a measurement file of the built image, which is
that is orthogonal to Petridish. Please refer to §2.4.4 and             used for comparison with the measured hash value recorded
§7.1 for the detection approach in details.                             in the CVM’s attestation report.
    Finally, users cannot obtain other users’ prompts as                Attestable CVM Environment Both users and the LLM
the prompts and input KV cache are isolated in per-user                 provider verify the CVM environment before transmitting
processes. Particularly, attacks that exploit the vulnerabilities       any secrets. We implement the attestation process following
in LLM software, e.g., shared KV cache [37], cannot succeed             the challenge-response model. That is, a user or the LLM
either. This is because SPD relies on the underlying trusted            provider sends a challenge, i.e., a random nonce, to the Pro-
OS, rather than the LLM software, to enforce isolation among            cess Controller, initiating the attestation process. The Process
user prompts and input KV cache.                                        Controller first triggers the attestation of Nvidia GPU TEE
Model Confidentiality The secure channel and CVM iso-                   with the Nvidia Remote Attestation Service (NRAS) [52]. It
lation guarantee that the LLM remains confidential from                 includes the received challenge in its request to NRAS and in
adversaries on the cloud, including the cloud provider,                 turn receives a verifiable token from NRAS [54]. The Process
which is similar to how Petridish protects user prompt                  Controller then generates a CPU TEE attestation report with
confidentiality from such adversaries. On the other hand,               tool such as snpguest [50], providing the received challenge
Petridish’s design ensures that the per-user processes cannot           and the hash of the Nvidia token as input. As a result, the


                                                                    9
generated report not only measures and records the state of            score computation. While the service process asynchronously
the CPU TEE for verification, but also indicates the integrity         waits for all input attention scores to arrive, it continues to
of the GPU attestation and ensures their freshness. Finally,           compute matrices K , V and output attention scores. Once
the Process Controller returns the generated attestation report        all scores are ready, it computes the final attention scores
and the Nvidia token as a response.                                    with Theorem 1 and generates output tokens. Although
    After auditing the software stack and verifying the CVM            our prototype is based on the Llama model, our design
environment, users and the LLM provider can confidently                is generally applicable to other Transformer-based LLMs.
transmit their encrypted secrets to the Process Controller             We also note that the GLOO [59] backend transfers tensors
via secure channels established with the Diffie-Hellman key            via the host, which incurs non-trivial overhead (See §6.2).
exchange protocol [45].                                                We discuss the portability of Petridish design and the reasons
LLM Supply and Service Process Initialization We consider              why other popular communication backends, e.g., NCCL [60],
two ways for the LLM provider to supply the LLM to                     are not suitable in §7.2.
the Process Controller. First, if the LLM software is open
source, we include it in building the CVM image as part                6. Evaluation
of the software stack audit process. During runtime, the
LLM provider transmits only LLM parameters via the secure              In this section, we primarily focus on the question: Does
channel. Alternatively, the provider can encrypt and sign its          Petridish achieve high scalability and maintain compute
closed source LLM software binary and parameters, include              efficiency? To answer this, we evaluate Petridish’s perfor-
the encrypted data and signatures in the CVM image, and                mance comparing to two existing confidential inferencing
during runtime transmit only the cryptographic keys via the            approaches (§2.3). As for empirical security evaluation on
secure channel. In either case, the Process Controller decrypts        prompt stealing attacks (§2.4.3), we refer the readers to the
the LLM parameters within the CVM before initializing the              experiments and analysis in Tan et al [14].
service process. The Process Controller stores the decrypted           Evaluation setup Without special mention, all evaluations
LLM parameters as a read-only in-memory file and creates               were conducted in an Azure’s CVM, NCCads H100 v5 [61].
the service process. It grants the service process read-only           The CVM equips with an Nvidia H100 GPU with 94 GB of
access to the in-memory file containing the LLM parameters,            memory, 40 AMD EPYC Genoa processor cores, and 320
which allows the service process to initialize as usual.               GB of system memory. Confidential computing features, i.e.,
LLM Parameter Read-only Sharing and Per-user Pro-                      AMD SEV-SNP [28] and Nvidia GPU CC [33], are enabled.
cess Initialization The Process Controller maps the LLM                     The software stack in the CVM includes Ubuntu 24.04
parameters as read-only memory. After creating per-user                with kernel version 6.11.0, Nvidia open driver version
processes and restricting their network capabilities, the              570.158.01, CUDA 12.8, Python 3.12.3, and PyTorch 2.7.1.
Process Controller shares the read-only LLM parameters with            For LLM, we utilizes Llama 3 [62] with 8B, Llama 3.2 with
these processes. To achieve this, the Process Controller lever-        1B and 3B, and Code Llama [63] with 7B, 13B and 34B
ages PyTorch’s CUDA MemPool to integrate a customized                  parameters.
memory allocator, which allocates GPU memory specifically                   For overhead evaluation, we measure the latency both
only for the LLM parameters [55]. To be more precise,                  with Nvidia MPS [48] enabled and disabled. We note that, to
it allocates GPU memory regions via cuMemCreate and                    use MPS, it requires no modifications to the implementation.
generates shareable handles via cuMemExportToShareable-                Performance Analysis We compare Petridish with two
Handle for inter-process sharing LLM parameters [56]. When             baselines: (1) No protection, where a LLM instance serves
creating per-user processes, the Process Controller sets the           all users within a single process (Figure 2a). It does not
CLONE NEWNET flag in clone system calls. This leverages                secure user prompts from the LLM provider and is intended
Linux namespaces to restrict the network capabilities of the           to demonstrate the upper bound of performance. (2) Full
per-user processes [57]. Then the Process Controller shares            isolation, where each user owns a per-user process that runs
the GPU memory handles with the per-user processes, which              a dedicated LLM instance (Figure 2c). Petridish is denoted
then import the allocated GPU memory regions via cuMemIm-              as SPD (Figure 2d). As mentioned in Evaluation Setup, we
portFromShareableHandle to access the LLM parameters                   measure and compare the performance both with Nvidia
for prefill [56]. This approach ensures that only authorized           MPS [48] enabled and disabled.
per-user processes can access the shared GPU memory,
preventing unauthorized access to the LLM parameters while             6.1. Scalability
maintaining isolation for the rest of memory.
Secure Partitioned Decoding We develop SPD based on                    Our evaluation includes 1 to 32 users, with both prompts
the Transformers library [58], adapting the Llama model by             and responses ranging from 64 to 512 tokens. We measure
monkey-patching its attention module. To be more precise,              the end-to-end latency for each user to receive the responses.
we modified the attention score computation to prioritize the          Figure 4, Figure 5 and Figure 6 summarize the main
computation of matrix Q. This enables the service process to           results, demonstrating that our approach scales effectively
promptly send Q to each per-user process asynchronously via            as the number of users, input/output tokens, and the model
the GLOO communication backend [59] for input attention                parameter size increase.


                                                                  10
                                  25                                                                                                              No Protection
                                                 Full Isolation (MPS)                                                                      1.5




                                                                                                           Average latency per token (s)
                                                 Full Isolation                                                                                   SPD
                                  20             SPD (MPS)                                                                                        Full Isolation
                                                                                                                                           1.2
  Normalized latency

                                                 SPD
                                  15                                                                                                       0.9
                                  10                                                                                                       0.6
                                      5                                                                                                    0.3
                                      0                                                                                                    0.0
                                          0       5       10        15        20    25      30                                                   1B          3B        7B         13B   34B
                                                               Number of users                                                                                 Model parameter size
Figure 4: Normalized latency with varying number of                                                        Figure 5: Average latency with varying model sizes, 8
users, Llama 3 (8B), 64 input and 64 output tokens. y = 1                                                  users, 64 input and 64 output tokens. The solid and dashed
indicates the latency of No Protection baseline.                                                           bars indicate with and without MPS respectively.

                                                          64        128       256     512                  smaller memory footprint. However, Petridish still faces high
  Average latency per token (s)




                                  0.22                                                                     overhead compared to the No protection approach (indicated
                                                                                                           as y = 1), which is the cost of isolating user prompts in
                                  0.19                                                                     per-user processes.
                                                                                                           Model Parameter Size Figure 5 shows that the token
                                  0.16
                                                                                                           generation slows down for all approaches when the size
                                  0.13                                                                     of model parameter increases. Not surprisely, No protection
                                                                                                           performs the best, while SPD is less affected by parameter
                                  0.10                                                                     size scaling compared to the Full isolation approach. In other
                         128           256      64
                                                 512                                                       words, Full isolation’s end-to-end latency scales at a higher
                       Number of output tokens                                                             rate than that of SPD under the same conditions, when the
Figure 6: Average latency per generated token, with                                                        model size increases from 1B to 34B.
varying number of input and output tokens, Llama 3 (8B)
                                                                                                           Number of Input/Output Tokens Figure 6 shows that both
and 8 users. Varying groups of bars indicate varying output
                                                                                                           input and output token counts have negligible impact on
token counts. The four bars in each group indicate varying
                                                                                                           token generation. As the counts increase, the latency per
input token counts. The solid and dashed bars indicate with
                                                                                                           token remains relatively stable as decoding each token has
and without MPS respectively.
                                                                                                           static overhead, or even slightly reduces because the initial
                                                                                                           cost is amortized across the tokens.
                                              Q proj
                                  6           Send Q
  Normalized latency




                                              KV Proj                                                      6.2. Compute efficiency
                                  5           Out Attn
                                  4           Recv Pvt
                                              Merge                                                        We further breakdown the overhead of Petridish to demon-
                                  3           MLP
                                                                                                           strate the sources of overhead.
                                  2                                                                        Overhead breakdown of SPD SPD introduces overhead
                                  1                                                                        mainly due to (1) the absence of batch processing in per-
                                  0                                                                        user processes, and (2) communication between per-user
                                      No Protection After Q        After KV    After OA CC disabled        processes and the service process. We present SPD’s latency
                                                               Measurements                                breakdown in Figure 7. The seven latency components align
Figure 7: Overhead breakdown. All are measured with                                                        with the processing steps in Figure 3, except that we partition
Llama 3 (8B), 32 users, 64 input and 64 output tokens. MPS                                                 the “QKV projection” into “Q proj” and “KV proj”. The first
is enabled except for No Protection.                                                                       bar in Figure 7 represents the breakdown of No protection,
                                                                                                           while other bars represent that of SPD in different conditions.
                                                                                                           The three bars in the middle differ in when Q is sent,
Number of Users The Full isolation approach faces inher-                                                   right after the computation of Q (“After Q”), K and V
ent scalability limitations due to GPU memory constraints                                                  (“After KV”), or the output attention scores (“After OA”).
because it provides separate LLM instances for each user.                                                  The last bar is measured with GPU CC disabled. We note
As shown in Figure 4, it exhibits significant latency degra-                                               Figure 7 is measured with CUDA Event on GPU side, which
dation with increasing user counts. In contrast, Petridish                                                 is slightly different from the end-to-end latency in previous
achieves superior scalability, as it maintains a substantially                                             measurements.


                                                                                                      11
Processes compete for GPU resources Temporally ignoring                 attacks exploit vulnerabilities in specific CVM implemen-
the communication when comparing the first four bars, we                tations, for example, the deterministic encryption. Since
observe that the computation right after sending Q is much              Petridish’s design does not impose any restrictions on its
slowed down compared to the No protection baseline, while               underlying infrastructure (See discussion on portability in
other components have negligible overhead. It is because                §7.2), it is compatible with any existing and future solutions
the per-user processes compete with the service process for             that enhance the security of CVM [67], [68].
GPU resources once they receive Q. Sending Q after output                   Notably, Chuang et al. [66] recently extracted the Provi-
attention computation can avoid such competition, but the               sioning Certification Key (PCK) of Intel TDX, successfully
service process must be blocked and keep waiting for the                compromising the chain of trust of its attestation mechanism.
input scores, which results in slightly higher total latency as         This attack severely undermines the trust established between
it fails to overlap communication with computation.                     Petridish with users and the LLM provider. However, thanks
High communication overhead of GPU CC The last bar                      to Petridish’s portable design, the attestation issues can be
in Figure 7 shows SPD’s latency breakdown with GPU CC                   mitigated by deploying Petridish on CVM implementations
disabled. Its total latency is about 1/3 of that with GPU               that are not vulnerable to this issue.
CC enabled since the communication overhead reduces by                  Attacks on OS Similarly, Petridish inherits vulnerabilities
about 5×. This is because the GLOO backend [59] transfers               in the software stack, especially the guest OS due to its
tensors via the host, where the GPU driver and GPU device               large attack surface [69], [70]. To mitigate such attacks,
encrypt and decrypt all transferred data going through the              Petridish can leverage existing techniques that enhance the
PCIe, incurring high overhead [34] (§2.2.3). We expect this             security of OS, for example, containerizing each process
overhead can be much reduced and even fully eliminated                  with gVisor [71], [72] to minimize the OS’s attack surface.
with newer version GPU CC designs that enable TEE-IO [35]               Another series of techniques that focus on protecting data in
or better support of communication across processes that                use against a compromised OS [38], [39], [40] also enhances
share the same GPU (See §7.2).                                          Petridish’s security.

7. Discussion                                                           7.2. Portability and Deployment of Petridish
In this section, we first discuss attacks out of our threat
model and how Petridish may works with existing solutions               Portability across LLMs Petridish is portable across different
to mitigate them. Then, we discuss the portability of Petridish         decoder-only LLMs such as GPT [20] and Llama [21] series.
design and how to deploy it under different situations. Finally,        Although our prototype and evaluation focus on the Llama
we discuss the limitations of Petridish and its future work.            series, we believe Petridish is applicable to other decoder-
                                                                        only LLMs, e.g., the GPT series. This is because our attention
7.1. Mitigating Attacks Out of Scope                                    decomposition (Theorem 1) is general without relying on
                                                                        any specific implementations.
7.1.1. Prompt-leakage Injection Attacks. A malicious                    Portability across Architectures Petridish is portable across
service process may induce the per-user processes to leak               different CPU and accelerator architectures, provided they
prompts by injecting instructions like “repeat the prompt”              support a CVM spanning across CPU and the accelerators.
into output token sequences via manipulating the token                  We deploy our prototype in an Azure CVM because, at the
generation (§2.4.4). Although this attack is out of our                 time of writing, it is the only CVM available on public
Honest-but-Curious (HBC) threat model, Petridish can work               cloud that enables CC on an NVIDIA H100 GPU [33]. We
with attention-based detection methods to defend against it.            believe Petridish can be deployed in CVMs with various
Recently, Hung et al. [41] discover the distraction effect in           architectures, such as combinations of AMD SEV-SNP [28]
attention computation when injected instructions are present.           and ARM CCA [29], together with NVIDIA Blackwell [35]
Building on this discovery, Attention Tracker effectively               and security-enhanced TPU [73], [74].
detects prompt injection attacks by monitoring attention                Portability across Communication Backends We use
computation [41]. Similarly, users can identify the distrac-            GLOO [59] as it is general. In contract, even if NCCL [60]
tion effect, so to detect prompt-leakage injection attacks              typically performs better in scenarios involves GPUs, it
performed by the service process, via monitoring Petridish’s            requires that each process has exclusive access to a GPU,
input attention scores within the per-user processes.                   which is not suitable for our evaluation platform. CUDA
                                                                        IPC, as well as PyTorch’s Queue and Pipe, can share tensors
7.1.2. Attacks on TCB. Petridish introduces a novel                     across processes without copying. However, so far they do
application-level approach to confidential prompting. Its               not support asynchronous IO. As a result, they are even
security is built on top of the CVM hardware and the software           less efficient. Fortunately, one can expect that the newer
stack, e.g., guest OS. As such, it inherits both the security           version of GPU CC in Nvidia Blackwell [35] with TEE-IO
guarantees and the vulnerabilities of the underlying TCB.               can reduce and even eliminate the overhead of encrypted
Attacks on CVM Petridish does not defend against attacks                communication between CPU and GPU. Any CUDA IPC
that compromise the CVM [64], [65], [66]. Many of these                 based asynchronous IO support will also benefit Petridish.


                                                                   12
Per-user CVM Deployment without Consensus In §3.1,                          Differential Privacy (DP) protects prompt confidentiality
we assume all users and the LLM provider trust the shared               by injecting noise into token distributions [3], [77], gener-
software stack. This consensus may not be practical when                ating few-shot random examples [4], or tuning the input
considering the OS has a large attack surface. Petridish                prompts [78]. However, these methods are task-specific and
is portable to per-user CVM instead of per-user process                 compromise output invariance.
deployment. This deployment does not require the consensus                  Multi-Party Computation (MPC)-based methods utilize
on software stack, as each user can independently trust their           secret sharing that cryptographically splits a number, either
own stack. However, to secure model confidentiality, this               an LLM weight or a prompt token, into multiple numbers.
setup requires the cloud provider to restrict outbound network          Then they distribute each split to an untrusted party. The user
from per-user CVMs. This means that the LLM provider                    derives the LLM responses by cryptographically combining
must trust the cloud provider, or both being the same party,            the outputs of these parties. This technique suffers from
e.g., Google Gemini and Google Cloud.                                   multiple problems. First, the untrusted parties must not
Achieve Consensus with A Smart Contract It is interesting               collude. Second, secret sharing is not efficient for all LLM
to view the initialization of Petridish’s CVM (§3.3) from               operations. Recognizing its inefficiency, the authors modify
a decentralized perspective. We do not care which party                 the model, e.g., using ReLU instead of SoftMax [79], or
initializes the CVM, as long as all parties agree on its initial        use a much smaller model distilled specially [80], requiring
state. We can standardize the properties and initialization             model re-training and violating output invariance.
steps of the CVM with a smart contract, hardcoding the target               Homomorphic encryption (HE) enables computation on
platform, versions of the open source software, minimum                 encrypted data and is often combined with MPC to secure
number of participants that triggers the initialization and so          user privacy in LLM inference [10], [81], [82], [83]. How-
on. This smart contract can be certified by an authoritative            ever, its significant overhead impedes its use in real-world
auditor like CertiK [75], which eases the process of earning            applications, particularly for nonlinear functions, even in the
trust from users and the LLM provider.                                  cases of equipping dedicated hardware. Recent works [81],
                                                                        [82], [83] replace these functions with approximations, which
The More Trust, the Better Performance In §3.1, we                      may reduce model accuracy or require model re-training,
assume that all users untrust each other and assign each                thereby impeding the use of existing well-trained models.
user a dedicated process. In practice, some users may trust                 Data anonymization refers to techniques that remove or
each other to some extent, e.g., a group of employees in a              obscure personally identifiable information (PII) from data to
company. In this case, Petridish can assign a process shared            prevent the identification of individuals. Recent work [5], [6],
by multiple users, reducing overhead of process management              [7], [8] proposes masking or replacing sensitive segments
and context switching.                                                  in prompts, such as names and locations. However, the
                                                                        anonymization process either fails to protect the secrets or
7.3. Limitations and Future Work                                        leads to meaningless responses. This occurs when the secrets
                                                                        are essential for the task. For example, considering a user
                                                                        asks for directions to a specific location, anonymizing the
Petridish has its limitations, which bring new opportunities
                                                                        location address will result in an unusable response.
for future works. We hope our design and discussion will
                                                                            Obfuscation generates redundant instances, such as
spark further exploration on confidential prompting.
                                                                        privacy-preserving representations [84], pseudo prompts [85],
Protection of LLM Response Petridish secures user prompts               and noise tokens [86], which are mixed with authentic ones
but not the responses against an untrusted LLM provider.                to confuse attackers. The key idea is that attackers cannot
This implies that the full isolation approaches (Figure 2b              distinguish authentic instances from fake ones, whereas users
and Figure 2c) are still needed when user would like to                 with private prior knowledge can identify the authentic data.
secure both the prompts and the responses. Petridish offers             However, these obfuscation based methods usually lead to
an alternative approach for different scenarios instead of              high computational overhead due to the redundant instances,
replacing existing confidential inferencing solutions.                  and are vulnerable to attacks based on statistical analysis.
Enhanced TCB As discussed in §7.1, Petridish inherits
the vulnerabilities of the underlying TCB. Incorporating                9. Concluding Remarks
techniques that enhance the security of Petridish’s TCB,
e.g., [67], [68], into Petridish can further enhance Petridish’s        Cloud-hosted LLM service is becoming pervasive in our
security against attacks that are out of the current scope.             daily lives. However, it raises privacy concerns since users
                                                                        must submit their prompts to the cloud, which are handled by
                                                                        the LLM service in plaintext. Petridish combines confidential
8. Related Work                                                         computing and secure partitioned decoding (SPD) to protect
                                                                        user prompts from adversaries in the cloud, including both
In recent years, researchers have explored various approaches           the cloud provider and the LLM provider. It fully utilizes the
beyond confidential computing to preserve user privacy in               confidential computing capabilities of modern hardware to
LLM inference under the assumption of an untrusted LLM                  establish trust and protect both user prompts and the LLM.
provider [76].                                                          SPD further secures user prompts from the LLM provider


                                                                   13
while retaining the full utility of the LLM service, achieving
efficient and scalable confidential prompting. Our proposed
solution has the potential to enable privacy-preserving LLM
applications such as chatbots and AI assistants that involve
sensitive data such as personal information, clinical records,
and financial documents.




                                                                 14
References                                                                             [21] H. Touvron, T. Lavril, G. Izacard, X. Martinet, M.-A. Lachaux,
                                                                                            T. Lacroix, B. Rozière, N. Goyal, E. Hambro, F. Azhar et al.,
                                                                                            “LLaMA: Open and efficient foundation language models,” arXiv
[1]   Confidential Computing Consortium (CCC), “The Linux Foundation
                                                                                            preprint arXiv:2302.13971, 2023.
      Projects,” 2023, Accessed: 2025-11-10. [Online]. Available: https:
      //confidentialcomputing.io                                                       [22] A. Vaswani, N. Shazeer, N. Parmar, J. Uszkoreit, L. Jones, A. N.
                                                                                            Gomez, Ł. Kaiser, and I. Polosukhin, “Attention is all you need,”
[2]   J. Lin, J. Tang, H. Tang, S. Yang, W.-M. Chen, W.-C. Wang, G. Xiao,
                                                                                            Advances in Neural Information Processing Systems (NeurIPS 2017),
      X. Dang, C. Gan, and S. Han, “AWQ: Activation-aware weight
                                                                                            vol. 30, 2017.
      quantization for LLM compression and acceleration,” in MLSys, 2024.
                                                                                       [23] M. Ott, S. Edunov, A. Baevski, A. Fan, S. Gross, N. Ng, D. Grangier,
[3]   T. Wu, A. Panda, J. T. Wang, and P. Mittal, “Privacy-preserving
                                                                                            and M. Auli, “fairseq: A fast, extensible toolkit for sequence modeling,”
      in-context learning for large language models,” arXiv preprint
                                                                                            in Proceedings of the 2019 Conference of the North American Chapter
      arXiv:2305.01639, 2023.
                                                                                            of the Association for Computational Linguistics: Human Language
[4]   X. Tang, R. Shin, H. A. Inan, A. Manoel, F. Mireshghallah, Z. Lin,                    Technologies, NAACL-HLT 2019, Minneapolis, MN, USA, June 2-7,
      S. Gopi, J. Kulkarni, and R. Sim, “Privacy-preserving in-context                      2019, Demonstrations, W. Ammar, A. Louis, and N. Mostafazadeh,
      learning with differentially private few-shot generation,” arXiv preprint             Eds. Association for Computational Linguistics, 2019, pp. 48–53.
      arXiv:2309.11765, 2023.                                                               [Online]. Available: https://doi.org/10.18653/v1/n19-4009
[5]   Z. Shen, Z. Xi, Y. He, W. Tong, J. Hua, and S. Zhong, “The fire thief            [24] M. Shoeybi, M. Patwary, R. Puri, P. LeGresley, J. Casper,
      is also the keeper: Balancing usability and privacy in prompts,” arXiv                and B. Catanzaro, “Megatron-LM: Training multi-billion parameter
      preprint arXiv:2406.14318, 2024.                                                      language models using model parallelism,” CoRR, vol. abs/1909.08053,
                                                                                            2019. [Online]. Available: http://arxiv.org/abs/1909.08053
[6]   Z. Zeng, J. Wang, J. Yang, Z. Lu, H. Zhuang, and C. Chen, “Priva-
      cyRestore: Privacy-preserving inference in large language models via             [25] R. Pope, S. Douglas, A. Chowdhery, J. Devlin, J. Bradbury, J. Heek,
      privacy removal and restoration,” arXiv preprint arXiv:2406.01394,                    K. Xiao, S. Agrawal, and J. Dean, “Efficiently scaling transformer
      2024.                                                                                 inference,” Proceedings of Machine Learning and Systems, vol. 5, pp.
                                                                                            606–624, 2023.
[7]   Y. Chen, T. Li, H. Liu, and Y. Yu, “Hide and Seek (HaS): A
      lightweight framework for prompt privacy protection,” arXiv preprint             [26] I. Gim, G. Chen, S.-s. Lee, N. Sarda, A. Khandelwal, and L. Zhong,
      arXiv:2309.03057, 2023.                                                               “Prompt Cache: Modular attention reuse for low-latency inference,”
                                                                                            arXiv preprint arXiv:2311.04934, 2023.
[8]   Z. Kan, L. Qiao, H. Yu, L. Peng, Y. Gao, and D. Li, “Protecting user
      privacy in remote conversational systems: A privacy-preserving frame-            [27] F. McKeen, I. Alexandrovich, A. Berenzon, C. V. Rozas, H. Shafi,
      work based on text sanitization,” arXiv preprint arXiv:2306.08223,                    V. Shanbhogue, and U. R. Savagaonkar, “Innovative instructions and
      2023.                                                                                 software model for isolated execution.” Hasp@ isca, vol. 10, no. 1,
                                                                                            2013.
[9]   Z. Huang, W.-j. Lu, C. Hong, and J. Ding, “Cheetah: Lean and fast
      secure two-party deep neural network inference,” in 31st USENIX                  [28] AMD, “AMD secure encrypted virtualization (AMD SEV),” https:
      Security Symposium (USENIX Security 22), 2022, pp. 809–826.                           //www.amd.com/en/developer/sev.html.
[10] M. Hao, H. Li, H. Chen, P. Xing, G. Xu, and T. Zhang, “Iron: Private              [29] ARM, “Introducing Arm Confidential Compute Architecture,” https:
     inference on transformers,” Advances in Neural Information Processing                  //developer.arm.com/documentation/den0125/400.
     Systems (NeurIPS 2022), vol. 35, pp. 15 718–15 731, 2022.                         [30] Tinfoil, “Tinfoil Enclaves: A Technical Overview,” 2025, Accessed:
[11] Wiki, “Petri dish,” 2025, Accessed: 2025-11-10. [Online]. Available:                   2025-11-10. [Online]. Available: https://tinfoil.sh/blog/2025-01-10-tin
     https://en.wikipedia.org/wiki/Petri dish                                               foil-enclaves-overview
[12] J. Vig and Y. Belinkov, “Analyzing the structure of attention in a                [31] ——, “Publish, Audit, Attest: How Tinfoil Builds Trust,” 2025,
     transformer language model,” arXiv preprint arXiv:1906.04284, 2019.                    Accessed: 2025-11-10. [Online]. Available: https://tinfoil.sh/blog/20
                                                                                            25-01-13-how-tinfoil-builds-trust
[13] K. Clark, U. Khandelwal, O. Levy, and C. D. Manning, “What
     does bert look at? an analysis of bert’s attention,” arXiv preprint               [32] ——, “Detailed Attestation Architecture,” 2025, Accessed: 2025-11-
     arXiv:1906.04341, 2019.                                                                10. [Online]. Available: https://docs.tinfoil.sh/verification/attestation-a
                                                                                            rchitecture
[14] Y. Tan, X. Shen, Y. Shen, M. Backes, and Y. Zhang, “On the
     effectiveness of prompt stealing attacks on in-the-wild prompts,” in              [33] Nvidia, “Nvidia confidential computing,” 2023, Accessed: 2025-11-10.
     2025 IEEE Symposium on Security and Privacy. IEEE, 2025, pp.                           [Online]. Available: https://www.nvidia.com/en-us/data-center/soluti
     392–410.                                                                               ons/confidential-computing

[15] L. Gao, R. Peng, Y. Zhang, and J. Zhao, “Dory: Deliberative prompt                [34] ——, “NVIDIA Confidential Computing Whitepaper,” 2023, Accessed:
     recovery for LLM,” arXiv preprint arXiv:2405.20657, 2024.                              2025-11-10. [Online]. Available: https://images.nvidia.com/aem-dam
                                                                                            /en-zz/Solutions/data-center/HCC-Whitepaper-v1.0.pdf
[16] Z. Sha and Y. Zhang, “Prompt stealing attacks against large language
     models,” arXiv preprint arXiv:2402.12959, 2024.                                   [35] ——, “NVIDIA Blackwell Architecture,” 2025, Accessed: 2025-11-10.
                                                                                            [Online]. Available: https://www.nvidia.com/en-us/data-center/techno
[17] Y. Yang, X. Zhang, Y. Jiang, X. Chen, H. Wang, S. Ji, and Z. Wang,                     logies/blackwell-architecture/
     “Prsa: Prompt reverse stealing attacks against large language models,”
                                                                                       [36] M. Russinovich, “Azure AI Confidential Inferencing: Technical Deep-
     CoRR, 2024.
                                                                                            Dive,” https://techcommunity.microsoft.com/t5/azure-confidential-com
[18] A. Radford, J. Wu, R. Child, D. Luan, D. Amodei, I. Sutskever et al.,                  puting/azure-ai-confidential-inferencing-technical-deep-dive/ba-p/4
     “Language models are unsupervised multitask learners,” OpenAI blog,                    253150, 2024.
     vol. 1, no. 8, p. 9, 2019.
                                                                                       [37] G. Wu, Z. Zhang, Y. Zhang, W. Wang, J. Niu, Y. Wu, and Y. Zhang,
[19] T. Brown, B. Mann, N. Ryder, M. Subbiah, J. D. Kaplan, P. Dhariwal,                    “I know what you asked: Prompt leakage via kv-cache sharing in
     A. Neelakantan, P. Shyam, G. Sastry, A. Askell et al., “Language                       multi-tenant llm serving,” in Proceedings of the 2025 Network and
     models are few-shot learners,” Advances in Neural Information                          Distributed System Security (NDSS) Symposium. San Diego, CA, USA,
     Processing Systems (NeurIPS 2020), vol. 33, pp. 1877–1901, 2020.                       2025.
[20] J. Achiam, S. Adler, S. Agarwal, L. Ahmad, I. Akkaya, F. L. Aleman,               [38] S. Zhao, M. Li, Y. Zhang, and Z. Lin, “vSGX: Virtualizing SGX
     D. Almeida, J. Altenschmidt, S. Altman, S. Anadkat et al., “GPT-4                      enclaves on AMD SEV,” in 2022 IEEE Symposium on Security and
     technical report,” arXiv preprint arXiv:2303.08774, 2023.                              Privacy (SP). IEEE, 2022, pp. 321–336.



                                                                                  15
[39] W. Wang, L. Song, B. Mei, S. Liu, S. Zhao, S. Yan, X. Wang, D. Meng,            [59] Facebook, “Gloo: Collective Communications Library,” 2023,
     and R. Hou, “The road to trust: Building enclaves within confidential                Accessed: 2025-11-10. [Online]. Available: https://github.com/faceb
     VMs,” arXiv preprint arXiv:2402.11438, 2024.                                         ookincubator/gloo
[40] C. Li, S.-s. Lee, and L. Zhong, “Blindfold: Confidential mem-                   [60] Nvidia, “NVIDIA Collective Communications Library (NCCL),”
     ory management by untrusted operating system,” arXiv preprint                        2025, Accessed: 2025-11-10. [Online]. Available: https://developer.nv
     arXiv:2412.01059, 2024.                                                              idia.com/nccl
[41] K.-H. Hung, C.-Y. Ko, A. Rawat, I. Chung, W. H. Hsu, P.-Y. Chen                 [61] Microsoft, “Microsoft Azure NCCads H100 v5 sizes series,” https:
     et al., “Attention Tracker: Detecting prompt injection attacks in LLMs,”             //learn.microsoft.com/en-us/azure/virtual-machines/sizes/gpu-acceler
     arXiv preprint arXiv:2411.00348, 2024.                                               ated/nccadsh100v5-series, 2024.

[42] Linux developers, “Linux Kernel,” 2025, Accessed: 2025-11-10.                   [62] Meta, “Llama 3,” https://llama.meta.com/llama3/, 2024.
     [Online]. Available: https://github.com/torvalds/linux                          [63] “Code Llama,” https://ai.meta.com/blog/code-llama-large-language-m
[43] Nvidia, “NVIDIA Linux open GPU kernel module,” 2025, Accessed:                       odel-coding/, 2024.
     2025-11-10. [Online]. Available: https://github.com/NVIDIA/open-g               [64] M. Li, Y. Zhang, H. Wang, K. Li, and Y. Cheng, “CIPHERLEAKS:
     pu-kernel-modules                                                                    Breaking constant-time cryptography on AMD SEV via the ciphertext
                                                                                          side channel,” in 30th USENIX Security Symposium (USENIX Security
[44] O. Goldreich, Foundations of cryptography: volume 2, basic applica-
                                                                                          21), 2021, pp. 717–732.
     tions. Cambridge university press, 2001, vol. 2.
                                                                                     [65] Y. Yuan, Z. Liu, S. Deng, Y. Chen, S. Wang, Y. Zhang, and Z. Su,
[45] W. Diffie and M. E. Hellman, “New directions in cryptography,” in                    “CipherSteal: Stealing input data from TEE-shielded neural networks
     Democratizing cryptography: the work of Whitfield Diffie and Martin                  with ciphertext side channels,” in 2025 IEEE Symposium on Security
     Hellman, 2022, pp. 365–390.                                                          and Privacy (SP). IEEE, 2025, pp. 4136–4154.
[46] Nvidia, “CUDA C++ Programming Guide, Interprocess                               [66] J. Chuang, A. Seto, N. Berrios, S. van Schaik, C. Garman, and
     Communication,” 2025, Accessed: 2025-11-10. [Online]. Available:                     D. Genkin, “ TEE.fail: Breaking Trusted Execution Environments
     https://docs.nvidia.com/cuda/cuda-c-programming-guide/#interproce                    via DDR5 Memory Bus Interposition ,” in 2026 IEEE Symposium
     ss-communication                                                                     on Security and Privacy (SP). Los Alamitos, CA, USA: IEEE
[47] M. Milakov and N. Gimelshein, “Online normalizer calculation for                     Computer Society, May 2026, pp. 1894–1912. [Online]. Available:
     softmax,” arXiv preprint arXiv:1805.02867, 2018.                                     https://doi.ieeecomputersociety.org/10.1109/SP63933.2026.00101

[48] Nvidia, “Nvidia MPS,” 2025. [Online]. Available: https://docs.nvidia.           [67] K. D. Duy, J. Kim, H. Lim, and H. Lee, “INCOGNITOS: A practical
     com/deploy/mps/index.html                                                            unikernel design for full-system obfuscation in confidential virtual
                                                                                          machines,” in 2025 IEEE Symposium on Security and Privacy (SP).
[49] PyTorch, “PyTorch source code,” 2025, Accessed: 2025-11-10.                          IEEE, 2025, pp. 4192–4209.
     [Online]. Available: https://github.com/pytorch/pytorch
                                                                                     [68] H. Qin, Z. Song, W. Zhang, S. Huang, W. Yao, G. Liu, X. Jia, and
[50] VirTEE, “snpguest,” 2025, Accessed: 2025-11-10. [Online]. Available:                 H. Du, “Protecting encrypted virtual machines from nested page fault
     https://github.com/virtee/snpguest                                                   controlled channel,” in Proceedings of the Thirteenth ACM Conference
                                                                                          on Data and Application Security and Privacy, 2023, pp. 165–175.
[51] Nvidia, “nvTrust,” 2025, Accessed: 2025-11-10. [Online]. Available:
     https://github.com/NVIDIA/nvtrust                                               [69] B. Schlüter, S. Sridhara, A. Bertschi, and S. Shinde, “WeSee: Using
                                                                                          malicious #VC interrupts to break AMD SEV-SNP,” in 2024 IEEE
[52] ——, “NVIDIA GPU Attestation Guide,” 2025, Accessed: 2025-11-10.                      Symposium on Security and Privacy (SP). IEEE, 2024, pp. 4220–
     [Online]. Available: https://github.com/NVIDIA/nvtrust/blob/main/gu                  4238.
     est tools/README.md
                                                                                     [70] B. Schlüter, S. Sridhara, M. Kuhne, A. Bertschi, and S. Shinde,
[53] Github, “Github Actions,” 2025, Accessed: 2025-11-10. [Online].                      “HECKLER: Breaking confidential VMs with malicious interrupts,” in
     Available: https://github.com/features/actions                                       33rd USENIX Security Symposium (USENIX Security 24), 2024, pp.
                                                                                          3459–3476.
[54] Nvidia, “Example code for remote attestation of Nvidia GPU,” 2025,
     Accessed: 2025-11-10. [Online]. Available: https://github.com/NVIDI             [71] Google, “gvisor: The container security platform,” 2025, Accessed:
     A/nvtrust/blob/main/guest tools/attestation sdk/tests/end to end/har                 2025-11-10. [Online]. Available: https://gvisor.dev/
     dware/test remote gpu.py
                                                                                     [72] E. Perot, “Running stable diffusion on gpu with gvisor,” 2025,
[55] PyTorch, “PyTorch CUDA MemPool,” 2025, Accessed: 2025-11-10.                         Accessed: 2025-11-10. [Online]. Available: https://gvisor.dev/blog/20
     [Online]. Available: https://docs.pytorch.org/docs/stable/generated/tor              23/06/20/gpu-pytorch-stable-diffusion/
     ch.cuda.memory.MemPool.html                                                     [73] J. Yagnik, “Private ai compute: our next step in building private
[56] Nvidia, “CUDA C++ Programming Guide, Shareable Memory                                and helpful ai,” 2025, Accessed: 2025-11-12. [Online]. Available:
     Allocations,” 2025, Accessed: 2025-11-10. [Online]. Available:                       https://blog.google/technology/ai/google-private-ai-compute/
     https://docs.nvidia.com/cuda/cuda-c-programming-guide/#shareabl                 [74] Google, “Google private ai compute: Extending on-device privacy
     e-memory-allocations                                                                 with the power of the cloud,” 2025, Accessed: 2025-11-12. [Online].
[57] Linux developers, “Linux Clone System Call,” 2025, Accessed:                         Available: https://services.google.com/fh/files/misc/private ai compu
     2025-11-10. [Online]. Available: https://man7.org/linux/man-pages/m                  te technical brief.pdf
     an2/clone.2.html                                                                [75] CertiK, “Smart Contract Audit,” 2025. [Online]. Available:
[58] T. Wolf, L. Debut, V. Sanh, J. Chaumond, C. Delangue, A. Moi,                        https://www.certik.com/products/smart-contract-audit
     P. Cistac, T. Rault, R. Louf, M. Funtowicz, J. Davison, S. Shleifer,            [76] K. Edemacu and X. Wu, “Privacy preserving prompt engineering: A
     P. von Platen, C. Ma, Y. Jernite, J. Plu, C. Xu, T. L. Scao,                         survey,” arXiv preprint arXiv:2404.06001, 2024.
     S. Gugger, M. Drame, Q. Lhoest, and A. M. Rush, “Transformers:
                                                                                     [77] A. Panda, T. Wu, J. T. Wang, and P. Mittal, “Differentially private
     State-of-the-art natural language processing,” in Proceedings of
                                                                                          in-context learning,” arXiv preprint arXiv:2305.01639, 2023.
     the 2020 Conference on Empirical Methods in Natural Language
     Processing: System Demonstrations. Online: Association for                      [78] J. Hong, J. T. Wang, C. Zhang, Z. Li, B. Li, and Z. Wang, “DP-OPT:
     Computational Linguistics, Oct. 2020, pp. 38–45. [Online]. Available:                Make large language model your privacy-preserving prompt engineer,”
     https://www.aclweb.org/anthology/2020.emnlp-demos.6                                  2024.



                                                                                16
[79] Y. Akimoto, K. Fukuchi, Y. Akimoto, and J. Sakuma, “Privformer:
     Privacy-preserving transformer with MPC,” in 2023 IEEE 8th Euro-
     pean Symposium on Security and Privacy (EuroS&P). IEEE, 2023,
     pp. 392–410.
[80] D. Li, R. Shao, H. Wang, H. Guo, E. P. Xing, and H. Zhang,
     “MPCFormer: fast, performant and private transformer inference with
     MPC,” arXiv preprint arXiv:2211.01452, 2022.
[81] X. Liu and Z. Liu, “LLMs can understand encrypted prompt:
     Towards privacy-computing friendly transformers,” arXiv preprint
     arXiv:2305.18396, 2023.
[82] Q. Pang, J. Zhu, H. Möllering, W. Zheng, and T. Schneider, “BOLT:
     Privacy-preserving, accurate and efficient inference for transformers,”
     in 2024 IEEE Symposium on Security and Privacy (SP). IEEE, 2024,
     pp. 4753–4771.
[83] T. Chen, H. Bao, S. Huang, L. Dong, B. Jiao, D. Jiang, H. Zhou, J. Li,
     and F. Wei, “THE-X: Privacy-preserving transformer inference with
     homomorphic encryption,” arXiv preprint arXiv:2206.00216, 2022.
[84] Y. Yao, F. Wang, S. Ravi, and M. Chen, “Privacy-preserving lan-
     guage model inference with instance obfuscation,” arXiv preprint
     arXiv:2402.08227, 2024.
[85] P. Mai, Y. Yang, R. Yan, R. Ye, and Y. Pang, “ConfusionPrompt:
     Practical private inference for online large language models,” Available
     at SSRN 5046754, 2023.
[86] M. Zhang, T. He, T. Wang, L. Mi, N. Mireshghallah, B. Chen, H. Wang,
     and Y. Tsvetkov, “LatticeGen: Hiding generated text in a lattice for
     privacy-aware large language model generation on cloud,” in Findings
     of the Association for Computational Linguistics: NAACL 2024, 2024,
     pp. 2674–2690.




                                                                                17
Appendix

1. Proof of Theorem 1

   Let Q ∈ Rd be the query vector. Partition the key
and value matrices K, V ∈ Rlen×d into input and output
components:
                                     
                     Kin           Vin
             K=            , V =          .
                    Kout           Vout
Compute the attention scores s by:
    s = QK ⊤ = QKin     ⊤       ⊤
                                                               
                            QKout   = sin                     sout ,
              ⊤               ⊤
where sin = QKin and sout = QKout . Define the softmax
denominators:
                           len
                           X
                  γ=             exp(si ) = γin + γout ,
                           i=1

with
               len
                X in                             len
                                                  X out

       γin =           exp(sin,i ),     γout =            exp(sout,i ).
               i=1                                i=1

The attention output is:
           len
           X   exp(si )
σ(s)V =                      Vi
           i=1
                       γ
                  len                            len
                                                                               !
                     in                             out
           1       X                              X
         =                 exp(sin,i )Vin,i +             exp(sout,i )Vout,i
           γ       i=1                            i=1
                           lenin
                                                    !
           γin          1 X
         =                       exp(sin,i )Vin,i
            γ          γin i=1
                           lenout
                                                     !
             γout      1 X
           +                      exp(sout,i )Vout,i
               γ     γout i=1
           γin                 γout
                 σ(sin )⊤ Vin +         σ(sout )⊤ Vout .
                                                       
         =                                                                (2)
            γ                       γ
Thus,
                                  γin
         σ(QK ⊤ )V =                          ⊤
                                         σ(QKin )Vin
                              γin + γout
                                    γout        ⊤
                              +            σ(QKout )Vout ,                (3)
                                γin + γout
which completes the proof.




                                                                                18
