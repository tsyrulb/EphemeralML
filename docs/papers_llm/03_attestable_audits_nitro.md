                                                                Attestable Audits: Verifiable AI Safety Benchmarks
                                                                      Using Trusted Execution Environments


                                                              Christoph Schnabl 1 Daniel Hugenroth 1 Bill Marino 1 Alastair R. Beresford 1


                                                                   Abstract                                   interest (Casper et al., 2024; Raji et al., 2020; Mökander,
                                                                                                              2023), including data exfiltration by involved actors (Eriks-
                                                Benchmarks are important measures to evaluate
                                                                                                              son et al., 2025) or models that intentionally underperform
arXiv:2506.23706v1 [cs.AI] 30 Jun 2025




                                                safety and compliance of AI models at scale.
                                                                                                              during evaluations (van der Weij et al., 2025).
                                                However, they typically do not offer verifiable
                                                results and lack confidentiality for model IP and             To address these challenges, we investigate how users can
                                                benchmark datasets. We propose Attestable Au-                 verify they are interacting with a compliant AI system under
                                                dits, which run inside Trusted Execution Environ-             realistic constraints: when model providers do not share
                                                ments and enable users to verify interaction with a           weights, auditors only share code and data with regulators,
                                                compliant AI model. Our work protects sensitive               and systems run on untrusted third-party infrastructure.
                                                data even when model provider and auditor do not
                                                                                                              We propose Attestable Audits (§3), a three-step verifica-
                                                trust each other. This addresses verification chal-
                                                                                                              tion protocol, where auditors and model providers securely
                                                lenges raised in recent AI governance frameworks.
                                                                                                              load models, audit code, and datasets into hardware-backed
                                                We build a prototype demonstrating feasibility on
                                                                                                              Trusted Execution Environments (TEEs), run benchmarks,
                                                typical audit benchmarks against Llama-3.1.
                                                                                                              and cryptographically attest and publish results to a public
                                                                                                              registry for user verification. We use TEEs from Confiden-
                                                                                                              tial Computing (CC, §2) to isolate execution and encrypt
                                         1. Introduction                                                      memory. We demonstrate through a prototype (§5) based on
                                         Audits are an essential tool in the modern AI safety land-           AWS Nitro Enclaves that benchmarks yield expected results
                                         scape as models become more capable (Aschenbrenner,                  at 2.2× the cost of CPU and 21.7× that of GPU inference.
                                         2024) and potentially more dangerous (Barrett et al., 2023;
                                         Anthropic, 2023; OpenAI, 2024), particularly in agentic en-          2. Confidential Computing (CC)
                                         vironments (Chan et al., 2023). Recognizing these risks, sev-
                                         eral AI regulations (Parliament & Union, 2024; Office, 2024;         Confidential Computing (CC) ensures that critical systems
                                         The White House, 2023), policy initiatives, and AI princi-           protect data-in-transit, data-at-rest, and data-in-use. This is
                                         ples (House of Commons, 2024; Solaiman, 2023; Kapoor                 achieved by TEEs, privileged execution modes supported by
                                         et al., 2024) have mandated audits, but decision-makers              modern CPUs—conceptually, a small, shielded, encrypted
                                         often lack the technical information needed to evaluate au-          computer inside a computer. Backed by secure hardware,
                                         diting tools (Reuel et al., 2025). This creates a critical           TEEs prevent interference by the host/hypervisor and en-
                                         gap between policy and implementation that Technical AI              crypt all memory to thwart even physical attacks by attack-
                                         Governance aims to close through tools, such as verifiable           ers. This makes CC attractive for deployments at otherwise
                                         audits (Reuel et al., 2025). However, current audits rely            untrusted cloud service providers (CSPs) as long as the
                                         on contracts or manual processes, and verification remains           vendor of the secure hardware is trusted (Chen et al., 2023).
                                         challenging due to restricted model access and data privacy          In contrast to first generation process-based TEEs (e.g., In-
                                         concerns (Longpre et al., 2024a;b; Carlini et al., 2024; Cen         tel SGX, Arm TrustZone), second generation TEEs (e.g.,
                                         & Alur, 2024). Furthermore, misaligned incentives between            AMD SEV-SNP, Intel TDX, AWS Nitro) support full
                                         stakeholders can result in audits that do not serve the public       VMs (Costan, 2016; Pinto & Santos, 2019; Intel, 2025;
                                            1
                                              Department of Computer Science and Technology, Uni-             AMD, 2025). This helps them overcome resource limita-
                                         versity of Cambridge. Correspondence to: Christoph Schnabl           tions, especially memory, that previously made ML work-
                                         <cs2280@cst.cam.ac.uk>.                                              loads difficult (Mo et al., 2024). Whereas many CC appli-
                                                                                                              cations focus on confidentiality properties, our work also
                                         Proceedings of the 42 nd International Conference on Machine         leverages its integrity guarantees which can provide zero-
                                         Learning, Vancouver, Canada. PMLR 267, 2025. Copyright 2025
                                         by the author(s).                                                    knowledge-proof-like guarantees (Russinovich et al., 2024).

                                                                                                          1
                  Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments




Figure 1. Overview of the Attestable Audit protocol. A The auditor and regulator agree on audit code AC and dataset AD. B Optionally,
the provider prepares a (quantized) version Mq of model M , verifiable via attestation AM →Mq . C In the audit, the auditor loads
encrypted AC + AD into a fresh TEE and the provider loads encrypted M . D The audit result R and attestation AM q,AC+AD→R are
published to a transparency log L. E The user confidentially sends prompt p to M (or Mq ) in a TEE, receiving x and an attestation
verifying provenance and M ’s compliance. F The user may disclose (p, x, AM,p→x,R ) to the regulator to show audit deficits.


Clients can verify they are talking to a service inside a            i.e., the attestation includes hashes of model weights and
TEE through Remote Attestation (RA). In RA, the secure               code, and audit verifiability (G2), i.e., outputs are bound
chip signs a chain of measurements, called Platform Con-             to an approved audit version. The system must maintain
figuration Registers (PCRs), using a non-extractable secret          confidentiality (G3) of model weights (protecting IP) and
key. The PCRs cover the Trusted Computing Base (TCB),                audit data to prevent “cheating”. These guarantees are hard
consisting of firmware and the loaded enclave base im-               to achieve in non-CC setups but enable more robust audits,
age. Including the enclave base image enables revocation             especially for closed-source systems. Transparency (G4)
when vulnerabilities, e.g., side-channels (Li et al., 2021),         requires publishing base image, model, and audit digests,
active attacks (Schlüter et al., 2024), and memory alias-           with verifiable build steps. Finally, the system must enforce
ing (De Meulemeester et al., 2025), are discovered.                  statelessness (G5) to prevent prompt residue and covert
                                                                     channels (Shumailov et al., 2025), and output verifiability
We use AWS Nitro Enclaves (AWS, 2024) as the CC plat-
                                                                     (G6) to authenticate model responses during interaction.
form for our prototype. Our protocol is compatible with
other CC platforms, such as Intel TDX and AMD SEV-SNP,               We assume the existence of Network adversaries (A1)
but we leave those implementations for future work. We               who can intercept, tamper with, or spoof communication
expect that alternatives allow for smaller TCBs and lower            between components, but exclude DoS attacks. For Physical
overhead. Importantly, these can also integrate with GPUs            and Privileged adversaries (A2), with capabilities such as
featuring CC support, such as Nvidia’s H100 (Apsey et al.,           RAM snapshots, VM rollbacks, and side-channel attacks.
2023) to allow for larger models. However, these eventually
face limits, e.g., there is no multi-GPU support. As such,           3.2. Requirements
our conservative choice of a smallest common-denominator
technology, ensures our design supports these challenges.            We use three standard cryptographic primitives available in
                                                                     libraries like L IB S ODIUM. First, we require a pre-image
                                                                     and collision-resistant hashing function. Second, we require
3. Attestable Audits                                                 an IND-CCA secure key encapsulation mechanism (KEM)
We present Attestable Audits as a three-step design depicted         to allow two parties to share a symmetric key. The re-
in Figure 1. First, model providers may prepare their model.         ceiver generates (pk, sk) ← KEM.K EY G EN () and shares
Then, providers and auditors load the audit code and data            pk. Then sender uses pk to generate a key and cipher-
into a TEE, which runs benchmarks and publishes attested             text c, k ← KEM.E NCAPSULATE(pk). The receiver re-
results. Finally, users receive output attestations to verify        covers k using KEM.D ECAPSULATE(sk, c). Thirdly, we
interaction with an audited model.                                   require an IND-CCA secure encryption scheme (AEAD)
                                                                     with cx ← AEAD. ENCRYPT(k, x) to encrypt plaintext x
                                                                     under key k, and x ← AEAD. DECRYPT(k, cx ) to decrypt.
3.1. Security Goals and Threat Model
                                                                     Furthermore, we rely on functionality provided by the
The efficacy of the proposed system relies on the follow-
                                                                     TEE. First, we require attestation ({d, . . . }, PCR, σ) ←
ing security goals. We require model verifiability (G1),

                                                                 2
                    Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments



Table 1. Overview of common AI safety benchmarks. Underlined benchmarks were chosen as representative AC +AD for our evaluation.
Type                 Benchmarks
Discrete-Label       MMLU (Hendrycks et al., 2020), BoolQ (Clark et al., 2019), HellaSwag (Zellers et al., 2019)
Text-Similarity      XSum (Narayan et al., 2018), NarrativeQA (Kociský et al., 2017), CNN/DailyMail (Hermann et al., 2015)
Classifier-Judged    ToxicChat (Lin et al., 2023), BBQ (Parrish et al., 2022), RealToxicityPrompts (Gehman et al., 2020)
Retrieval            MSMARCO (Bajaj et al., 2018), Natural Questions (Kwiatkowski et al., 2019)
LLM-as-a-Judge       Chatbot Arena (Chiang et al., 2024)


ATTEST({d, . . . }) against the currently running TEE im-            Finally, the TEE encrypts the quantized model Mq using the
age. The attestation includes (1) the platform configuration         same symmetric key k and sends it to the model provider.
registers PCR that describe the loaded image, (2) auxiliary          It also publishes the attestation AM →Mq to a transparency
user-provided data {d, . . . }, and (3) a signature σ over all       log. This acts as evidence for third parties that they can
these signed with the TEE vendor’s secret key. We denote             accept models with the hash hMq as quantized versions of
attestations as Ain→out , for binding hashed input in =              models with the hash hM . The P REPARE step is convenient
H ASH(input) to hashed output out = H ASH(output).                   for practical deployments as some TEEs, e.g. the one for the
                                                                     audit, can only run against smaller models Mq . It allows the
We run the model code in a sandbox for isolation. Public
                                                                     model provider to deploy the full model M while convincing
model code can be included in the attested open-source base
                                                                     others that the audit of Mq is a valid approximation.
image, and only the weights need to remain confidential.
                                                                     The ATTESTABLE AUDIT protocol (Algorithm 2) runs au-
4. Protocols                                                         dit code AC and audit dataset AD against a (quantized)
                                                                     model Mq in a confidential and verifiable manner. For this
This section describes the main protocols of our Attestable          the TEE, as in the previous protocol, publishes an attestation
Audit scheme. Appendix A.1 describes used primitives and             with a KEM public key. Now both the model developer and
contains the pseudocode listings. The shown protocols omit           the audit provider use it to upload the encrypted model cMq
details, e.g. replay prevention and key rotation mechanisms,         and audit code/dataset cAC+AD to the TEE.
that are important for real-world implementations.
                                                                     Once the TEE has received both, it will create a sandbox
The P REPARE protocol (Algorithm 1) offers model devel-              and executes AC against Mq using the audit dataset AD.
opers the ability to quantize their models in a confidential         The sandbox ensures that malicious code that is part of
and verifiable manner. Practically, it enables the use of sub-       AC or Mq cannot interfere with the integrity of the overall
stantially smaller models with comparable performance. We            TEE logic or invalidate previous measurements. After the
discuss this ablation in Appendix A.4.2. Conceptually, it            execution, AC will output a single aggregated result R. The
illustrates the general, abstract attestation-and-encryption         TEE then publishes an attestation AMq ,AC,AD→R that binds
workflow, based on KEM and AEAD, that we likewise                    the hash of the model and audit to this result R. This is then
employ in our subsequent protocols.                                  published to a transparency log.
First the TEE boots from its secure image and generates a            The I NFERENCE protocol (Algorithm 3) allows users to
fresh KEM keypair pk, sk. It then attests to its boot image          confidentially interact with model M (or Mq ) confiden-
and the public key with a fresh attestation A to allow third         tially while being able to receive guarantees that it has re-
parties to verify the given pk was indeed generated inside a         ceived score R against the audit AC + AD. Different to
TEE that booted a trusted image. The third-party first com-          the previous protocols, the TEE first downloads the rele-
pares the PCR measurement against known trusted images               vant attestation documents from the previous steps from the
and then verifies the signature σ using the TEE’s vendor             transparency logs and includes these in its initial attestation.
public key (or respective attestation service).                      That provides a baseline guarantee to the user that their later
                                                                     prompts are not given to a different model.
Once the authenticity of the TEE has been confirmed, the
model provider calls (k, c) ← KEM.E NCAPSULATE(pk)                   Next, the model provider loads their model M into the TEE
and uses k to encrypt their model M . The encrypted model            using the familiar KEM+AEAD construction. The TEE will
cM and the encrypted key c are then sent to the TEE which            verify that the hash of the model matches with the value
can derive the same key using sk and decrypt the model. The          from the attestations and abort if that is not the case.
TEE then computes the quantized model Mq and measures
                                                                     Then the user sends the encrypted prompt cp to the TEE.
boths by computing their hashes hM and hMq .
                                                                     The TEE then starts a sandbox with the model M and runs


                                                                 3
                 Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments

it against the input p yielding output x. A fresh attestation
                                                                     Table 2. Trade-offs and benchmark scores across: (I) enclave, (II)
AM,p→x,R then provides the user also with a evidence that
                                                                     compute-constant, (III) cost-constant, vs. (IV) L40S GPU
links together model, audit result, prompt, and response.
Optionally the user can later use this attestation to proof
short-comings in the auditing process to a regulator.                 M ETRIC                         (I)     ( II )   ( III )    ( IV )
                                                                      P RICE / HR ($)                 0.38    0.19      0.38       0.89
5. Evaluation                                                         P RICE /100 K TOKEN ($)         5.80    2.61      3.01       0.12
                                                                      T OKEN / S                      1.84    2.04      3.54     202.00
We sample three AI-safety benchmarks (Table 1) to assess
Attestable Audits’ feasibility. With additional engineer-             BERT S CORE                    0.47     0.50      0.49       0.58
                                                                      T OXICITY RATE (%)             2.40     2.00      1.70       2.60
ing, we could integrate larger benchmark suites, such as              ACCURACY (%)                  51.40    52.60     48.60      58.90
COMPL-AI (Guldimann et al., 2024) and HELM (Liang
et al., 2023). We already employ zero-shot prompts from
both. Our implementation, written in Rust through bind-              performance. Doubling the number of CPUs from (I) to (III)
ings to llama.cpp (Gerganov, 2023), runs on AWS Nitro                increases the throughput by almost 2 token/s. We expect
Enclaves using Llama-3.1-8B-Instruct quantized to 4-bit to           larger instances to reduce the overhead by 2–5×.
reduce main memory footprint at an accuracy penalty.
We log input/output token counts and prompt/response de-             Security Model and audit verifiability (G1, G2) are
coding latencies, ignoring non-decoding overhead (e.g.,              achieved through the CC-powered audit step (Algorithm 2).
copying models into the enclave takes ≤2 minutes). We                The RA process binds the hashes of the quantised model Mq ,
issue 500 prompts per benchmark on: (I) a m5.2xlarge                 audit code AC, and dataset AD with the platform PCRs
instance running our protocol with enclaves enabled on 4             measurements. Confidentiality (G3) is end-to-end through
cores, (II) a version on m5.xlarge running on 4 cores,               the use of ephemeral keys inside the TEE. The AEAD chan-
(III) a cost-constant version running m5.2xlarge on 8                nel bound to the initial attestation protects data-in-transit
cores, and (IV) a SOTA baseline hosting the same model,              from a network adversary (A1). VM-level enclave isolation
but in fp16 precision on a cloud-based NVIDIA L40S,                  and full-memory encryption deny physical attackers (A2)
which uses roughly 90% of the available 48 GB VRAM                   access to data-in-use. Transparency (G4) follows from pub-
through vLLM at a price of 0.89 USD/hour.                            lishing the enclave base image, build scripts, content hashes,
                                                                     and the attestations AM →Mq , and AMq , AC+AD→R to L.
                                                                     Similar to Apple’s PCC (Apple, 2025), anyone can rebuild
Feasibility We demonstrate that models in Attestable Au-             and inspect the exact evaluation environment. For stateless-
dits achieve adequate performance (Table 2). In column (I),          ness (G5) each user session runs in a fresh VM-enclave
the quantized model’s zero-shot MMLU accuracy is 51.4%               that starts with zeroized RAM and not persistent storage
(57.4% excluding unparsable responses), similar to 54.6%             to eliminate prompt residue. Output integrity (G6) is guar-
on a non-quantized model (IV) at 58.9% and LLaMa’s                   anteed in the interaction step (Algorithm 3) analogously.
66.7% for 5-shot prompting (Touvron et al., 2023). The               For each prompt p the enclave returns (x, AM, p→x, R ), to
difference from (I–III) to (IV) is context size and precision;       bind H ASH(M ) ∥ p ∥ x ∥ R. Verifying AM, p→x, R against
from (IV) to LLaMa’s 66.7% is prompting. Summariza-                  L confirms the reply is from the audited model with score R.
tion yields a mean BERT score of ≈0.47 vs. ≈0.58 for the             Prompt-based model exfiltration during the user interaction
non-quantized version. On ToxicChat, 1.78% are jailbreak             step remains a residual gap (Carlini et al., 2024).
attempts. The quantized model fails to refuse and produces
toxic outputs in 2.4% of all test cases in (I) and 2.6% in
                                                                     Engineering Challenges Our approach works well for
the non-quantized case. Smaller differences between (I–III)
                                                                     smaller (in terms of tokens) hand-crafted datasets, as CPU
stem from stochastic top p sampling. A 4-bit quantized
                                                                     inference limits token throughput. Memory constraints of
model slightly degrades performance in benchmarks. We
                                                                     CC technology complicates hosting larger models. Enclaves
provide a more detailed feasibility analysis in Appendix A.4.
                                                                     do not have persistent memory but instead rely on a memory-
                                                                     mapped file system. As a result, the runtime memory re-
Trade-Offs Running inference on CPUs incurs a cost over-             quirements can be a multiple of the underlying base image.
head of 21.7× over GPU inference and suffers a 100× slow-            Due to this expansion, large files such as model weights
down. The use of enclaves costs 2× due to having to use              or datasets have to be transferred into the enclave during
a larger instance compared to (II) or sacrificing cores rel-         runtime. Cryptographic operations, e.g., when establishing
ative to (III). Memory capacity constraints forces the use           encrypted channels, add complex logic as well as additional
of smaller or quantized models. (III) hosts a 4-bit model            CPU demands. Many CC platforms come with limited
for comparability, but could host a 8-bit model for higher           documentation and lack easy-to-use software libraries. Ad-

                                                                 4
                 Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments

ditionally, a constant portion of main memory needs to be            can accommodate other post-training steps, e.g., fine-tuning.
reserved for the host system and thus remains unavailable
                                                                     While we presented our work in the context of LLMs, it gen-
to the enclave, which is at least 64 MiB (AWS, 2024), but
                                                                     eralizes to other AI/ML systems. For instance, the operator
for (I) is closer to 500 MiB, or 1.5% of available memory.
                                                                     of a self-driving car can use Attestable Audits to prove later,
                                                                     e.g., in court after an accident, that the very model that drove
6. Related Work                                                      the vehicle at a given time has been correctly audited. Note,
                                                                     that our infrastructure also prevents human-mistakes such
Hardware-Attested Integrity DeepAttest (Chen et al.,
                                                                     as mixing up audit results or accidentally deploying a wrong
2019) binds models and code to TEEs for CNNs but lacks
                                                                     model version. It also naturally provides reproducibility for
audit traceability and targets on-premise. Nevo et al. (2024)
                                                                     benchmarks during the scientific publication process.
protect weights, while we extend this to audit datasets and
code. OpenMined (2023) uses TEEs for evaluation but
lacks generality and reproducibility. Our system integrates          8. Conclusion
attestation into a transparent, regulator-facing pipeline.
                                                                     Our Attestable Audits design uses TEEs to load audit code
                                                                     (AC), audit data (AD), and model weights (M ) into an
Cryptographic Private Inference zkML (South et al.,                  enclave, execute AI-safety benchmarks, and publish cryp-
2024) generates SNARKs for inference verification, but is            tographic proofs binding results to exact AC + AD + M
orders of magnitude slower. FHE-LoRA (Frery et al., 2025)            hashes. Our AWS Nitro Enclaves prototype runs three stan-
uses encrypted low-rank adaptation. SONNI (Sperling &                dard benchmarks at 21.7× the cost of GPU inference, with
Kulkarni, 2025) and Proof-of-Training (Sun & Zhang, 2023)            a CPU-constant variant at 2× overhead. Our protocol can
focus on weight and data lineage, while we verify runtime            be used for Verifiable Audits (Reuel et al., 2025) (§5.4.1)
behavior. PPFL (Mo et al., 2021) protects training gradients         without exposing sensitive IP. Our main limitation stems
with TEEs, while we apply them to secure model evaluation.           from CPU inference, but we expect this overhead to reduce
                                                                     as GPU-capable enclaves become more readily available.
Audit Frameworks & Governance Audit Cards (Staufer                   By shifting AI governance from ex post enforcement to
et al., 2025) show audit gaps, especially in reproducibility         ex ante certifiable deployment, Attestable Audits reduces
and verification. Mökander et al. (2023) propose a layered          compliance and transaction costs of governing AI systems.
taxonomy without cryptographic guarantees. Grollier et al.
(2024) show audits can enable fairwashing. Dong et al.
(2024) and Leslie et al. (2023) focus on post-hoc safety,
                                                                     Policy Brief
whereas we provide pre-deployment guarantees. Brundage               This work directly addresses a topic that is critical to the
et al. (2020) stress the importance of verifiable claims.            enforcement of any AI regulation, or, more broadly, any AI
                                                                     governance policy: when regulators or auditors lack direct
7. Discussion & Limitations                                          access to a model or dataset due to privacy or competition
                                                                     concerns, how can they ensure it complies with the rele-
Our prototype has a high overhead in terms of runtime and            vant requirements? By introducing a method for verifiable
costs. Large parts of this can be attributed to the CPU-based        benchmarking of AI systems running on third-party infras-
inference that is required by the underlying CC technology.          tructure, we help bridge this gap and enable AI developers
A production-ready implementation using CC-compatible                to provide clear assurances about their models and datasets
GPUs likely has an overhead as small as 5×. We leave this,           to regulators, auditors, or any other stakeholders — without
and the other suggested extensions below, for future work.           exposing private assets such as model weights or propri-
Our architecture requires the participating parties to trust         etary data. By removing these barriers, our approach could
the hardware vendor of the CC technology, in our case AWS.           incentivize more AI providers to enter regulated markets
However, all steps can be run on multiple CC technologies            (Reuters, 2023) or, differently, to enroll in voluntary pre-
independently such that parties can later choose which attes-        deployment testing by third parties (Field, 2024). Separately,
tation they trust. We note that while this increases integrity       because our method can help shift the cost of benchmark-
guarantees (trust any), the model and audit confidentiality is       based audits from resource-constrained (Aitken et al., 2022)
reduced, as a single broken TEE can leak the sensitive data.         regulators to the AI developers who may be best-positioned
                                                                     to bear the expense of TEEs and, thus, the audits them-
Our prototype requires a quantized model due to technical            selves, we lower the overhead associated with creating and
limitations of the chosen CC technology. An implementa-              enforcing AI regulations or AI governance policies. Given
tion using a CC-compatible GPU can run the native Llama-3            these benefits, future AI legislation might consider explicitly
model securely. However, a preparation step will still be nec-       endorsing or encouraging such techniques.
essary for larger models that do not fit on a single GPU and

                                                                 5
                 Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments

Acknowledgements                                                    AWS. AWS Nitro Enclaves, 2024. https://aws.
                                                                     amazon.com/ec2/nitro/nitro-enclaves/.
We would like to thank the anonymous reviewers for their             Last accessed December 2024.
valuable feedback and suggestions, which helped improve
this paper. Christoph is supported by Corpus Christi College,       Bajaj, P., Campos, D., Craswell, N., Deng, L., Gao, J., Liu,
the German Academic Exchange Service, and the Studiens-               X., Majumder, R., McNamara, A., Mitra, B., Nguyen,
tiftung des Deutschen Volkes. Daniel is supported by Nokia            T., Rosenberg, M., Song, X., Stoica, A., Tiwary, S., and
Bell Labs and Light Squares.                                          Wang, T. MS MARCO: A Human Generated MAchine
                                                                      Reading COmprehension Dataset, 2018. URL https:
Impact Statement                                                      //arxiv.org/abs/1611.09268.

Attestable Audits advance technical AI governance by al-            Barrett, A. M., Hendrycks, D., Newman, J., and Nonnecke,
lowing auditors, and users to securely verify AI model com-           B. Actionable Guidance for High-Consequence AI Risk
pliance. It mitigates risks of misuse or harmful outputs from         Management: Towards Standards Addressing AI Catas-
AI systems through the use of trusted hardware that allows            trophic Risks, 2023. URL https://arxiv.org/
for rigorous audits without compromising sensitive data or            abs/2206.08966.
proprietary models. While this enhances transparency and
accountability, there remains a dependency on trusted hard-         Brundage, M. et al. Toward Trustworthy AI Development:
ware providers. Overall, we believe that Attestable Audits            Mechanisms for Supporting Verifiable Claims, 2020.
can reduce the risks associated with deploying powerful AI            URL https://arxiv.org/abs/2004.07213.
systems and contributes positively towards safer and more
trustworthy machine learning applications.                          Carlini, N., Paleka, D., Dvijotham, K. D., Steinke, T.,
                                                                      Hayase, J., Cooper, A. F., Lee, K., Jagielski, M., Nasr,
References                                                            M., Conmy, A., Yona, I., Wallace, E., Rolnick, D., and
                                                                      Tramèr, F. Stealing Part of a Production Language
Aitken, M., Leslie, D., Ostmann, F., Pratt, J., Margetts,             Model, 2024. URL https://arxiv.org/abs/
  H., and Dorobantu, C. Common Regulatory Capac-                      2403.06634.
  ity for AI. Technical report, The Alan Turing Insti-
  tute, 2022. URL https://doi.org/10.5281/      Casper, S., Ezell, C., Siegmann, C., Kolt, N., Curtis, T. L.,
  zenodo.6838946.                                 Bucknall, B., Haupt, A., Wei, K., Scheurer, J., Hobbhahn,
                                                  M., Sharkey, L., Krishna, S., Von Hagen, M., Alberti,
AMD. AMD Secure Encrypted Virtualization (SEV),   S., Chan, A., Sun, Q., Gerovitch, M., Bau, D., Tegmark,
  2025. https://www.amd.com/en/developer/         M., Krueger, D., and Hadfield-Menell, D. Black-Box
  sev.html. Last accessed April 2025.             Access is Insufficient for Rigorous AI Audits. In The
                                                  2024 ACM Conference on Fairness, Accountability, and
Anthropic.    Anthropic AI Risk Report, 2023.
                                                  Transparency, FAccT ’24, pp. 2254–2272. ACM, June
  URL      https://www-cdn.anthropic.com/
                                                  2024. doi: 10.1145/3630106.3659037. URL http:
 1adf000c8f675958c2ee23805d91aaade1cd4613/
                                                  //dx.doi.org/10.1145/3630106.3659037.
  responsible-scaling-policy.pdf.

Apple. Private Cloud Compute: A new frontier for AI                 Cen, S. H. and Alur, R. From Transparency to Account-
  privacy in the cloud, 2025. https://security.                       ability and Back: A Discussion of Access and Evidence
  apple.com/blog/private-cloud-compute/.                              in AI Auditing, 2024. URL https://arxiv.org/
  Last accessed April 2025.                                           abs/2410.04772.

Apsey, E., Rogers, P., O’Connor, M., and Nert-                      Chan, A., Salganik, R., Markelius, A., Pang, C., Rajku-
  ney, R.       Confidential computing on NVIDIA                      mar, N., Krasheninnikov, D., Langosco, L., He, Z., Duan,
  h100 GPUs for secure and trustworthy AI, 2023.                      Y., Carroll, M., Lin, M., Mayhew, A., Collins, K., Mo-
  https://developer.nvidia.com/blog/                                  lamohammadi, M., Burden, J., Zhao, W., Rismani, S.,
  confidential-computing-on-h100-gpus\                                Voudouris, K., Bhatt, U., Weller, A., Krueger, D., and Ma-
 -for-secure-and-trustworthy-ai/.            Last                     haraj, T. Harms from Increasingly Agentic Algorithmic
  accessed April 2025.                                                Systems. In 2023 ACM Conference on Fairness, Ac-
                                                                      countability, and Transparency, FAccT ’23, pp. 651–666.
Aschenbrenner, L.   Situational Awareness: The                        ACM, June 2023. doi: 10.1145/3593013.3594033.
  Decade Ahead, 2024.     Available at https://                       URL http://dx.doi.org/10.1145/3593013.
  situational-awareness.ai/.                                          3594033.

                                                                6
                Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments

Chen, H., Fu, C., Rouhani, B. D., Zhao, J., and Koushanfar,       Frery, J., Bredehoft, R., Klemsa, J., Meyre, A., and Stoian,
  F. DeepAttest: an end-to-end attestation framework for            A. Private LoRA Fine-Tuning of Open-Source LLMs
  deep neural networks. In Proceedings of the 46th Inter-           with Homomorphic Encryption. https://arxiv.
  national Symposium on Computer Architecture, ISCA                 org/abs/2505.07329, 2025. arXiv:2505.07329.
 ’19, pp. 487–498, New York, NY, USA, 2019. Associa-
  tion for Computing Machinery. ISBN 9781450366694.               Gehman, S., Gururangan, S., Sap, M., Choi, Y., and
  doi: 10.1145/3307650.3322251. URL https://doi.                    Smith, N. A. RealToxicityPrompts: Evaluating Neu-
  org/10.1145/3307650.3322251.                                      ral Toxic Degeneration in Language Models. CoRR,
                                                                    abs/2009.11462, 2020. URL https://arxiv.org/
Chen, H., Chen, H. H., Sun, M., Li, K., Chen, Z., and               abs/2009.11462.
  Wang, X. A verified confidential computing as a service
                                                                  Gerganov, G. llama.cpp: Port of LLaMA model in
  framework for privacy preservation. In 32nd USENIX
                                                                    pure C/C++, 2023. URL https://github.com/
  Security Symposium (USENIX Security 23), pp. 4733–
                                                                    ggerganov/llama.cpp.
  4750, 2023.
                                                                  Grollier, X., Kazilsky, Y., et al. Cheating Automatic
Chiang, W.-L., Zheng, L., Sheng, Y., Angelopoulos, A. N.,           LLM Benchmarks: Null Models Achieve High Scores
  Li, T., Li, D., Zhang, H., Zhu, B., Jordan, M., Gonzalez,         via Fairwashing. https://arxiv.org/abs/2410.
  J. E., and Stoica, I. Chatbot Arena: An Open Platform             07137, 2024. arXiv:2410.07137.
  for Evaluating LLMs by Human Preference, 2024. URL
  https://arxiv.org/abs/2403.04132.                               Guldimann, P., Spiridonov, A., Staab, R., Jovanović, N.,
                                                                   Vero, M., Vechev, V., Gueorguieva, A.-M., Balunović,
Clark, C., Lee, K., Chang, M., Kwiatkowski, T., Collins,            M., Konstantinov, N., Bielik, P., Tsankov, P., and Vechev,
  M., and Toutanova, K. BoolQ: Exploring the Surpris-               M. COMPL-AI Framework: A Technical Interpretation
  ing Difficulty of Natural Yes/No Questions. CoRR,                 and LLM Benchmarking Suite for the EU Artificial In-
  abs/1905.10044, 2019. URL http://arxiv.org/                       telligence Act. arXiv preprint arXiv:2410.07959, 2024.
  abs/1905.10044.                                                   URL https://arxiv.org/abs/2410.07959.

Costan, V. Intel SGX explained. IACR Cryptol, EPrint Arch,        Hendrycks, D., Burns, C., Basart, S., Zou, A., Mazeika, M.,
  2016.                                                             Song, D., and Steinhardt, J. Measuring Massive Multitask
                                                                    Language Understanding. CoRR, abs/2009.03300, 2020.
De Meulemeester, J., Wilke, L., Oswald, D., Eisenbarth, T.,         URL https://arxiv.org/abs/2009.03300.
  Verbauwhede, I., and Van Bulck, J. BadRAM: Practical
  memory aliasing attacks on trusted execution environ-           Hermann, K. M., Kociský, T., Grefenstette, E., Espe-
  ments. In 46th IEEE Symposium on Security and Privacy             holt, L., Kay, W., Suleyman, M., and Blunsom, P.
 (S&P), May 2025.                                                   Teaching Machines to Read and Comprehend. CoRR,
                                                                    abs/1506.03340, 2015. URL http://arxiv.org/
Dong, Y., Jiang, X., Liu, H., Jin, Z., Gu, B., Yang, M.,            abs/1506.03340.
  and Li, G. Generalization or Memorization: Data Con-
                                                                  House of Commons. Governance of Artificial Intelli-
  tamination and Trustworthy Evaluation for Large Lan-
                                                                    gence (AI). Technical report, House of Commons
  guage Models, 2024. URL https://arxiv.org/
                                                                    Science, Innovation and Technology Committee, 2024.
  abs/2402.15938.
                                                                    URL https://committees.parliament.uk/
                                                                    publications/45145/documents/223578/
Eriksson, M., Purificato, E., Noroozian, A., Vinagre, J.,
                                                                    default/.
  Chaslot, G., Gomez, E., and Fernandez-Llorca, D. Can
  We Trust AI Benchmarks? An Interdisciplinary Review             Intel.       Intel Trust Domain Extensions (Intel
  of Current Issues in AI Evaluation, 2025. URL https:              TDX), 2025.             https://www.intel.com/
  //arxiv.org/abs/2502.06559.                                        content/www/us/en/developer/tools/
                                                                     trust-domain-extensions/overview.html.
Field, H.      OpenAI and Anthropic agree to let                     Last accessed April 2025.
  U.S. AI Safety Institute test and evaluate
  new models.       CNBC, August 2024.        URL                 Kapoor, S., Bommasani, R., Klyman, K., Longpre, S., Ra-
  https://www.cnbc.com/2024/08/29/                                  maswami, A., Cihon, P., Hopkins, A., Bankston, K., Bi-
  openai-and-anthropic-agree-to-let-us\                             derman, S., Bogen, M., Chowdhury, R., Engler, A., Hen-
 -ai-safety-institute-test-models.html.                             derson, P., Jernite, Y., Lazar, S., Maffulli, S., Nelson, A.,
  Published 3:01 PM EDT, Updated 6:01 PM EDT.                       Pineau, J., Skowron, A., Song, D., Storchan, V., Zhang,

                                                              7
                 Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments

  D., Ho, D. E., Liang, P., and Narayanan, A. On the So-             Henderson, P. A Safe Harbor for AI Evaluation and Red
  cietal Impact of Open Foundation Models, 2024. URL                 Teaming, 2024a. URL https://arxiv.org/abs/
  https://arxiv.org/abs/2403.07918.                                  2403.04893.
Kociský, T., Schwarz, J., Blunsom, P., Dyer, C., Her-             Longpre, S., Mahari, R., Obeng-Marnu, N., Brannon, W.,
  mann, K. M., Melis, G., and Grefenstette, E. The Nar-              South, T., Kabbara, J., and Pentland, S. Data Authen-
  rativeQA Reading Comprehension Challenge. CoRR,                    ticity, Consent, and Provenance for AI Are All Bro-
  abs/1712.07040, 2017. URL http://arxiv.org/                        ken: What Will It Take to Fix Them? An MIT Ex-
  abs/1712.07040.                                                    ploration of Generative AI, mar 27 2024b. https://mit-
                                                                     genai.pubpub.org/pub/uk7op8zs.
Kwiatkowski, T., Palomaki, J., Redfield, O., Collins, M.,
 Parikh, A., Alberti, C., Epstein, D., Polosukhin, I., De-         Mo, F., Haddadi, H., Katevas, K., Marin, E., Perino, D.,
 vlin, J., Lee, K., Toutanova, K., Jones, L., Kelcey, M.,           and Kourtellis, N. PPFL: Privacy-preserving Federated
 Chang, M.-W., Dai, A. M., Uszkoreit, J., Le, Q., and               Learning with Trusted Execution Environments, 2021.
 Petrov, S. Natural questions: A benchmark for question             URL https://arxiv.org/abs/2104.14380.
 answering research. Transactions of the Association for
 Computational Linguistics, 7:452–466, 2019. doi: 10.              Mo, F., Tarkhani, Z., and Haddadi, H. Machine learning with
 1162/tacl a 00276. URL https://aclanthology.                       confidential computing: A systematization of knowledge.
 org/Q19-1026/.                                                     ACM computing surveys, 56(11):1–40, 2024.

Leslie, D., Rincón, C., Briggs, M., Perini, A., Jayadeva,         Mökander, J.   Auditing of AI: Legal, Ethical
  S., Borda, A., Bennett, S., Burr, C., Aitken, M., Katell,         and Technical Approaches.  Digital Society, 2,
  M., Fischer, C., Wong, J., and Kherroubi Garcia, I. AI            2023. URL https://api.semanticscholar.
  Fairness in Practice, 2023. URL https://zenodo.                   org/CorpusID:265045993.
  org/doi/10.5281/zenodo.10680527.
                                                                   Mökander, J., Schuett, J., Kirk, H. R., and Floridi, L. Au-
Li, M., Zhang, Y., Wang, H., Li, K., and Cheng, Y. CIPHER-          diting Large Language Models: A Three-Layered Ap-
   LEAKS: Breaking constant-time cryptography on AMD                proach. AI and Ethics, 4(4):1085–1115, 2023. doi:
   SEV via the ciphertext side channel. In 30th USENIX              10.1007/s43681-023-00289-2.
  Security Symposium (USENIX Security 21), pp. 717–732,
                                                                   Narayan, S., Cohen, S. B., and Lapata, M. Don’t Give
   2021.
                                                                     Me the Details, Just the Summary! Topic-Aware Con-
Liang, P., Bommasani, R., Lee, T., Tsipras, D., Soylu, D.,           volutional Neural Networks for Extreme Summarization,
  Yasunaga, M., Zhang, Y., Narayanan, D., Wu, Y., Kumar,             2018.
  A., Newman, B., Yuan, B., Yan, B., Zhang, C., Cosgrove,
                                                                   Nevo, S., Lahav, D., Karpur, A., Bar-On, Y., Bradley, H. A.,
  C., Manning, C. D., Ré, C., Acosta-Navas, D., Hudson,
                                                                     and Alstott, J. Securing AI Model Weights: Preventing
  D. A., Zelikman, E., Durmus, E., Ladhak, F., Rong, F.,
                                                                     Theft and Misuse of Frontier Models. RAND Corporation,
  Ren, H., Yao, H., Wang, J., Santhanam, K., Orr, L., Zheng,
                                                                     Santa Monica, CA, 2024. doi: 10.7249/RRA2849-1.
  L., Yuksekgonul, M., Suzgun, M., Kim, N., Guha, N.,
  Chatterji, N., Khattab, O., Henderson, P., Huang, Q., Chi,       Office, C. G.      Colorado Governor Signs AI
  R., Xie, S. M., Santurkar, S., Ganguli, S., Hashimoto, T.,         Regulation:   A New Era for AI Compliance,
  Icard, T., Zhang, T., Chaudhary, V., Wang, W., Li, X.,             2024.       URL https://aminiconant.com/
  Mai, Y., Zhang, Y., and Koreeda, Y. Holistic Evaluation            colorado-governor-signs-ai-regulation\
  of Language Models, 2023. URL https://arxiv.                      -a-new-era-for-artificial-i\
  org/abs/2211.09110.                                                ntelligence-compliance/.
Lin, Z., Wang, Z., Tong, Y., Wang, Y., Guo, Y., Wang, Y.,          OpenAI. OpenAI on Advanced AI Risks and Safety, 2024.
  and Shang, J. ToxicChat: Unveiling Hidden Challenges               URL https://openai.com/global-affairs/
  of Toxicity Detection in Real-World User-AI Conversa-              our-approach-to-frontier-risk/.
  tion, 2023. URL https://arxiv.org/abs/2310.
  17389.                                                           OpenMined. How to Audit an AI Model Owned by
                                                                     Someone Else (Part 1). https://openmined.org/
Longpre, S., Kapoor, S., Klyman, K., Ramaswami, A.,                  blog/ai-audit-part-1/, November 2023. Open-
  Bommasani, R., Blili-Hamelin, B., Huang, Y., Skowron,              Mined Blog; Last accessed May 2025.
  A., Yong, Z.-X., Kotha, S., Zeng, Y., Shi, W., Yang,
  X., Southen, R., Robey, A., Chao, P., Yang, D., Jia, R.,         Parliament, T. E. and Union, T. C. O. T. E. Regulation
  Kang, D., Pentland, S., Narayanan, A., Liang, P., and              (EU) 2024/1689 of the European Parliament and of the

                                                               8
                Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments

  Council of 13 June 2024 laying down harmonised rules           Solaiman, I. The gradient of generative AI release: Methods
  on artificial intelligence and amending certain Union            and considerations. arXiv preprint arXiv:2302.04844,
  legislative acts. http://data.europa.eu/eli/                     2023.
  reg/2024/1689/oj, 2024.
                                                                 South, T., Camuto, A., Jain, S., Nguyen, S., Mahari, R.,
Parrish, A., Chen, A., Nangia, N., Padmakumar, V., Phang,          Paquin, C., Morton, J., and Pentland, A. S. Verifi-
  J., Thompson, J., Htut, P. M., and Bowman, S. R. BBQ:            able evaluations of machine learning models using zk-
  A Hand-Built Bias Benchmark for Question Answer-                 SNARKs, 2024. URL https://arxiv.org/abs/
  ing, 2022. URL https://arxiv.org/abs/2110.                       2402.02675.
  08193.
                                                                 Sperling, L. and Kulkarni, Sandeep S. SONNI: Se-
Pinto, S. and Santos, N. Demystifying ARM TrustZone: A             cure Oblivious Neural Network Inference. https:
  comprehensive survey. ACM computing surveys (CSUR),              //arxiv.org/abs/2504.18974, 2025. To appear
  51(6):1–36, 2019.                                                in SECRYPT 2025; arXiv:2504.18974.
Raji, I. D., Smart, A., White, R. N., Mitchell, M., Ge-          Staufer, L., Yang, M., Reuel, A., and Casper, S. Audit Cards:
  bru, T., Hutchinson, B., Smith-Loud, J., Theron, D.,             Contextualizing AI Evaluations, 2025. URL https:
  and Barnes, P. Closing the AI Accountability Gap:                //arxiv.org/abs/2504.13839.
  Defining an End-to-End Framework for Internal Algo-
  rithmic Auditing. In Proceedings of the 2020 Conference        Sun, H. and Zhang, H.        Securely Proving Legiti-
  on Fairness, Accountability, and Transparency, FAT*              macy of Training Data and Logic for AI Regula-
 ’20, pp. 33–44, New York, NY, USA, 2020. Associa-                 tion. Preprint, 2023. URL https://blog.genlaw.
  tion for Computing Machinery. ISBN 9781450369367.                org/CameraReady/22.pdf.
  doi: 10.1145/3351095.3372873. URL https://doi.
  org/10.1145/3351095.3372873.                                   The White House.         White House Executive Or-
                                                                   der on Safe, Secure, and Trustworthy Ar-
Reuel, A., Bucknall, B., Casper, S., Fist, T., Soder, L.,          tificial Intelligence, 2023.      URL https:
  Aarne, O., Hammond, L., Ibrahim, L., Chan, A., Wills,            //www.whitehouse.gov/briefing-room/
  P., Anderljung, M., Garfinkel, B., Heim, L., Trask, A.,          presidential-actions/2023/10/30/
  Mukobi, G., Schaeffer, R., Baker, M., Hooker, S., So-            executive-order-on-the-safe-secure-\
  laiman, I., Luccioni, A. S., Rajkumar, N., Moës, N.,            and-trustworthy-development-and\
  Ladish, J., Bau, D., Bricman, P., Guha, N., Newman, J.,         -use-of-artificial-intelligence/.
  Bengio, Y., South, T., Pentland, A., Koyejo, S., Kochen-
  derfer, M. J., and Trager, R. Open Problems in Technical       Touvron, H., Lavril, T., Izacard, G., Martinet, X., Lachaux,
  AI Governance, 2025. URL https://arxiv.org/                      M.-A., Lacroix, T., Rozière, B., Goyal, N., Hambro, E.,
  abs/2407.14981.                                                  Azhar, F., Rodriguez, A., Joulin, A., Grave, E., and Lam-
                                                                   ple, G. LLaMA: Open and Efficient Foundation Lan-
Reuters.     OpenAI may leave the EU if regula-                    guage Models, 2023. URL https://arxiv.org/
  tions bite - CEO.    Reuters, May 2023. URL                      abs/2302.13971.
  https://www.reuters.com/technology/
  openai-may-leave-eu-if-regulations-\                           van der Weij, T., Hofstätter, F., Jaffe, O., Brown, S. F., and
  bite-ceo-2023-05-24/. Published 5:22 PM EDT,                     Ward, F. R. AI Sandbagging: Language Models can
  updated 2 years ago.                                             Strategically Underperform on Evaluations, 2025. URL
                                                                   https://arxiv.org/abs/2406.07358.
Russinovich, M., Fournet, C., Zaverucha, G., Benaloh, J.,
  Murdoch, B., and Costa, M. Confidential Computing              Zellers, R., Holtzman, A., Bisk, Y., Farhadi, A., and Choi, Y.
  Proofs: An alternative to cryptographic zero-knowledge.          HellaSwag: Can a Machine Really Finish Your Sentence?
  Queue, 22(4):73–100, 2024.                                       CoRR, abs/1905.07830, 2019. URL http://arxiv.
                                                                   org/abs/1905.07830.
Schlüter, B., Sridhara, S., Kuhne, M., Bertschi, A., and
  Shinde, S. Heckler: Breaking confidential VMs with
  malicious interrupts. In USENIX Security, 2024.
Shumailov, I., Ramage, D., Meiklejohn, S., Kairouz, P.,
  Hartmann, F., Balle, B., and Bagdasarian, E. Trusted
  Machine Learning Models Unlock Private Inference for
  Problems Currently Infeasible with Cryptography, 2025.
  URL https://arxiv.org/abs/2501.08970.

                                                             9
                  Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments

A. Appendix
                                                                         Algorithm 1 The model preparation protocol P REPARE run-
A.1. Protocol Primitive and Algorithm Listings
                                                                         ning inside the TEE.
The Attestable Audits protocols relies on three standard                  1: ▷ Create key and bind it to the booted TEE state
cryptographic primitives that are readily available in widely-            2: pk, sk ← KEM.K EY G EN ()
used cryptographic libraries such as L IB S ODIUM. Our pro-               3: A = ({pk}, PCR, σ) ← ATTEST({pk})
totype implementation uses classic cryptography algorithms                4: P UBLISH(A)
(SHA + EC25519 + AES-GCM), but real-world implemen-                       5: ▷ The developer verifies the attestation A and uses the
tations may opt for post-quantum secure alternatives.                        published key to encrypt their model M
                                                                          6: c, cM ← R ECEIVE E NCRYPTED M ODEL ()
First, we require a hashing function H ASH that fulfills the
                                                                          7: k ← KEM.D ECAPSULATE(sk, c)
standard requirements of pre-image and collision resistance.
                                                                          8: M ← AEAD.D ECRYPT(k, cM )
Second, we require an IND-CCA secure key encapsula-                       9: ▷ Quantize the model and attest to both the full model
tion mechanism (KEM) that allows a receiving party and                       M and the quantized version Mq
a sending party to securely share a symmetric key. The                   10: Mq ← Q UANTIZE(M )
pk, sk ← KEM.K EY G EN () method is used by the receiv-                  11: hM , hMq ← H ASH(M ), H ASH(Mq )
ing party to securely generate a secret-public key pair of               12: AM →Mq = (. . . , PCR, σ) ← ATTEST({hM , hMq })
which the public key pk is shared with others. The sending               13: ▷ Share the encrypted model with the developer and
party can then call k, c ← KEM.E NCAPSULATE(pk) to                           publish the final attestation
sample a new symmetric key k and an encrypted representa-                14: cMq ← AEAD.E NCRYPT(c, Mq )
tion c that is shared with the receiving party. The receiving            15: S END E NCRYPTED Q UANTIZED M ODEL(cMq )
party can then call k ← KEM.D ECAPSULATE(sk, c) to                       16: P UBLISH(AM →Mq )
derive the same key k.                                                   17: T ERMINATE E NCLAVE ()
Thirdly, we require an IND-CCA secure authenticated
encryption scheme (AEAD). It provides an cx ←
AEAD. ENCRYPT(k, x) method that encrypts the plain-
text x under the symmetric key k. The ciphertext                         Algorithm 2 The audit protocol ATTESTABLE AUDIT run-
cx can then be decrypted by either party using x ←                       ning inside the TEE.
AEAD. DECRYPT(k, cx ). Since AEAD schemes also pro-                       1: ▷ Create key and bind it to the booted TEE state
tect the integrity of the ciphertext, chances to cx will cause            2: pk, sk ← KEM.K EY G EN ()
AEAD. DECRYPT to fail.                                                    3: A = ({pk}, PCR, σ) ← ATTEST({pk})
                                                                          4: P UBLISH(A)
Furthermore, Attestable Audits relies on the following
                                                                          5: ▷ The developer verifies the attestation A and uses the
functionality provided by the TEE implementation. First,
                                                                             published key to encrypt their model M
we require a method that performs an attestation A =
                                                                          6: c1 , cMq ← R ECEIVE E NCRYPTED M ODEL ()
({d, . . . }, PCR, σ) ← ATTEST({d, . . . }) against the cur-
                                                                          7: k1 ← KEM.D ECAPSULATE(sk, c1 )
rently running TEE image. It includes (1) the platform
                                                                          8: Mq ← AEAD.D ECRYPT(k1 , CMq )
configuration registers PCR that describe the loaded image,
                                                                          9: ▷ The auditor verifies the attestation A and uses the
(2) auxiliary user-provided data {d, . . . }, and (3) a signature
                                                                             published key to encrypt their AC and AD
σ over all these signed with the TEE vendor’s secret key.
                                                                         10: c2 , cAC+AD ← R ECEIVE E NCRYPTEDAUDIT ()
We use the notational convention Ain→out for attestations
                                                                         11: k2 ← KEM.D ECAPSULATE(sk, c1 )
that capture the execution of code against a measured input
                                                                         12: AC, AD ← AEAD.D ECRYPT(k2 , cAC+AD )
in = H ASH(input) that resulted in out = H ASH(output).
                                                                         13: ▷ Run the audit AC + AD in a sandbox and gather the
Some of our algorithms run the model code in a sandbox to                    aggregated results R
ensure isolation where the model code might not be trusted.              14: s ← C REATE S ANDBOX(Mq , AC)
We note that this extra layer is not required where the model            15: R ← s.EXECUTE (AD)
structure is publicly known. In that case only the weights               16: hMq , hAC+AD ← H ASH(Mq ), H ASH(AC + AD)
must be kept confidential while the actual model code can                17: AMq ,AC+AD→R ← ATTEST({hMq , hAC+AD })
be part of the open-source base image that is being attested.            18: ▷ Share the results and the final attestation
                                                                         19: P UBLISH(R)
A.2. Benchmark Model Parameters                                          20: P UBLISH(AMq ,AC,AD→R )
                                                                         21: T ERMINATE E NCLAVE ()
Table 3 contains the parameter used for the LLaMa model
in each task. context window is the maximum number

                                                                    10
                 Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments

Algorithm 3 The inference protocol I NFERENCE running               the SUMMARIZATION task. For all tasks, prompts exceed-
inside the TEE.                                                     ing the context window are skipped, which is a practical
 1: ▷ Create key and bind it to the booted TEE state                decision rather than an intrinsic limitation of our protocol.
 2: AM →Mq , AMq ,AC,AD→R ← D OWNLOAD ()
                                                                    We constrain the output length via N LEN, since benchmark
 3: pk, sk ← KEM.K EY G EN ()
                                                                    runtime is limited by token-decoding speed. Sampling tem-
 4: A ← ATTEST({pk, AM →Mq , AMq ,AC,AD→R })
                                                                    peratures are set to 0.1 for SUMMARIZATION to favor fo-
 5: PUBLISH(A)
                                                                    cused, coherent summaries, 0.25 for CLASSIFICATION,
 6: ▷ The developer verifies the attestation A and uses the
                                                                    and 0.3 for TOXICITY detection. We apply nucleus
     published key to encrypt their model M
                                                                    sampling (TOP P) of 0.7 for both SUMMARIZATION and
 7: c1 , cM ← R ECEIVE E NCRYPTED M ODEL ()
                                                                    CLASSIFICATION, and 0.75 for TOXICITY.
 8: k1 ← KEM.D ECAPSULATE(sk, c1 )
 9: M ← AEAD.D ECRYPT(k1 , CM )
10: if HASH(M ) ̸= A.MODEL HASH then                                A.3. Benchmark Prompt Templates
11:     TERMINATE ENCLAVE ()
12: end if
13: ▷ The user verifies the attestation A and uses the pub-
                                                                        Table 4. Template prompts for the three benchmark tasks
     lished key to encrypt their prompt
14: c2 , cp ← R ECEIVE E NCRYPTED P ROMPT ()
                                                                    Task            Assembled Prompt
15: k2 ← KEM.D ECAPSULATE(sk, c2 )
16: p ← AEAD.D ECRYPT(k2 , cp )                                     Summarize       system: You are a professional summarizer.
                                                                    XSum            Please provide a structured summary of this doc-
17: ▷ Run the inference in a sandbox
                                                                                    ument, focusing on critical information.
18: s ← C REATE S ANDBOX (M)                                                        document: { document }
19: x ← s.E XECUTE(p)                                                               user: Summarize the document in 150 charac-
20: ▷ Return results to the user encrypted                                          ters or less.
21: AM,p→x,R ← ATTEST({H ASH(M ), p, x, R})                         Classify        system: You are a knowledgeable assistant.
22: c3 ← AEAD. ENCRYPT(k2 , {x, AM,p→x,R })                         MMLU            Please provide the correct answer to the question
23: SEND TO USER(c3 )                                                               based on the given context.
24: TERMINATE ENCLAVE ()                                                            question: { question }
                                                                                    choices: A) { choice A }
                                                                                             B) { choice B }
                                                                                             C) { choice C }
     Table 3. Model parameters for llama.cpp by task                                         D) { choice D }
                                                                                    user: GIVE YOUR ANSWER AS A, B, C, or
                                                                                    D ONLY. DO NOT PROVIDE ANY OTHER
                                                                                    TEXT.
 TASK           CONTEXT SIZE    N LEN   SEED   TEMP    TOP P
                                                                    Toxicity        system: You are a helpful assistant. Please re-
 S UMMARIZATION      8192        512    1337    0.1    0.7
                                                                    ToxicChat       spond to the following user message.
 C LASSIFICATION     4096        256    1337   0.25    0.7
                                                                                    user: { user input }
 T OXICITY           4096        256    1337    0.3    0.75


                                                                    This section briefly explains the prompts in Table 4. The
of input tokens the model sees at once, n len refers to the
                                                                    TASK column specifies each of the three tasks and the
number of new tokens the model will generate beyond the
                                                                    benchmark dataset, while the ASSEMBLED PROMPT col-
input, while seed is initializes the model’s random number
                                                                    umn shows the zero-shot prompts used for model infer-
generator so results are reproducible, and temp is a pa-
                                                                    ence, adapted from (Liang et al., 2023). Each prompt is
rameter that controls output temperature from 0 to 1 (lower
                                                                    divided into role-tagged paragraphs marked by uppercase
values more focused, higher more varied), and top p is the
                                                                    tokens: system, document, user, question, and
cumulative-probability threshold for nucleus sampling. The
                                                                    choices. For the SUMMARIZE XSUM task, we include
models samples at each step from the smallest set of tokens
                                                                    the DOCUMENT paragraph and instruct the model to produce
whose cumulative probability is at least p.
                                                                    a summary of roughly the same length as the reference (150
Through local experimentation, we selected parameters               characters). For the CLASSIFY MMLU task, we format the
that reflect typical workloads and yield robust performance.        QUESTION and CHOICES paragraphs and add an upper-
While specific choices can affect benchmark scores, adopt-          case USER directiv to ensure the model returns only the
ing these defaults is sufficient to demonstrate feasibility         choice letters. Finally, for the TOXICITY TOXICCHAT
of Attestable Audits. We allocate a slightly larger context         task, we SYSTEM instruction to be helpful, then paste the
window (CONTEXT SIZE) of 8192 compared to 4096 to                   raw USER input (which includes jailbreak attempts).

                                                               11
                   Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments




Figure 2. Token distribution for each of the three tasks for the two modes (I) enclave (top), (II) compute-constant (bottom)


A.4. Benchmark Feasibility                                              between the two configurations.
The following section provides additional context on the fea-
                                                                        A.4.2. I MPACT OF Q UANTIZATION
sibility of running AI safety benchmarks through Attestable
Audits. We argue that the results for each of the three
tasks are sound and align with expectations, then dive into
detailed timing measurements and token-decoding speeds,
comparing prompt decoding to output decoding. Finally, we
present an ablation study conducted outside of enclaves to
quantify the impact of quantization on benchmark perfor-
mance. Although prior research has thoroughly explored
quantization’s effects, we repeated these tests under iden-
tical parameters, prompts, model versions, and datasets to
eliminate any accidental discrepancies.

A.4.1. T OKEN D ISTRIBUTION
Figure 2 shows the PMF for response token distribution                  Figure 3. Cosine similarity scores of XSum BERT embeddings for
when running three different AI-safety benchmarks, both                 models quantized to 2-, 4-, and 8-bit
in the enclave and in the cost-constant alternative. The
compute-constant and GPU baselines are omitted for clar-
ity but follow a similar pattern. For the classification task,
we observe an unexpected peak at five tokens: start-of-                 Summarization: Figure 3 shows the cosine BERT-
sequence, end-of-sequence, start-of-header, end-of-header,              embedded similarity scores of expected XSum summaries,
and one token for A, B, C, or D. Smaller outliers occur when            for each quantization Q2 K, Q4 K M and Q8 0. Where 2-bit
the model fails to adhere to the prompt. Summarization, un-             and average of 0.443, 0.488 for 4-bit and, for 8 bit 0.49. We
surprisingly, follows a Gaussian shape, as models try to stick          can observer more variance for the 4 bit model.
to the 150-character prompt goal, yielding a median of 38
tokens in both modes. From our English-text experiments,                Classification: Figure 4 shows, for each model, the
a useful empirical rule is four characters per token. For               MMLU accuracy (computed only over valid, parseable re-
toxicity, the distribution is bimodal: in many cases, when              sponses) alongside its valid response rate. We observe that
prompted with a toxic response, the model either refuses to             most of the accuracy loss in the 2-bit model stems from its
deliver any tokens or issues a brief explanation of why it              higher rate of invalid responses. The 4-bit model achieves
cannot, forming one mode. The other mode (and everything                an accuracy of 56.2%, nearly matching the 57.5% of the
in between) covers non-toxic prompts but also successful                8-bit model, and both 4 and 8-bit models exhibit almost
length-attack jailbreaks. The PMF curves match very well                identical valid-response rates and overall performance.

                                                                   12
                  Attestable Audits: Verifiable AI Safety Benchmarks Using Trusted Execution Environments




Figure 4. MMLU accuracy scores per model (for valid responses
only) and valid response rate




Figure 5. Toxicity rate by quantization level, measured with a
DistilBERT-Base multilingual cased classifier


Toxicity: Figure 5 reports the fraction of responses clas-
sified as toxic by a DistilBERT–Base multilingual cased
toxicity classifier, over 500 toxicity-prompt trials for each
quantization level. The 2-bit model (Q2 K) emits toxic con-
tent 2.0% of the time (10/500), the 4-bit model (Q4 K M)
2.4% (12/500), and the 8-bit model (Q8 0) 2.2% (11/500).
The 0.4 pp difference between the lowest and highest rates
might indicate that aggressive quantization has minimal ef-
fect on the model’s propensity to generate toxic language.




                                                                 13
