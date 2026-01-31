White Paper


Confidential Computing: Powering
the Next Generation of Trusted AI

This paper explores Intel's strategy and solutions for improving security in the
growing Generative AI (GenAI) market with Confidential Computing.


                                                                       Authors                  Executive Summary
                                                           Paul O'Neill                         Organizations across a broad range of industries recognize Generative AI’s
                                                                                                transformative potential and have made it a top priority. And now these
                                     Senior Director,                                           companies are turning to their proprietary data—their strategic moat—to
                       Confidential Computing, Intel                                            extend the capabilities of AI beyond the foundational models and apply it to new
                                                    Matt Hopkins                                use cases that maximize the value of improved data insights.

                                                 Business Strategist,                           However, data integration challenges, privacy concerns, and security risks can
                                                                Intel                           slow down or derail companies’ GenAI pursuits. These obstacles are
                                                                                                particularly acute for companies operating in regulated industries, relying on
                                               Jesse Schrater                                   legacy systems, or managing hybrid computing environments.
                                Principal Engineer,                                             To help organizations realize GenAI’s benefits without compromising their risk
                    Data Center & AI Security, Intel                                            posture, Intel’s Confidential Computing technologies offer continuing
                                                                                                innovations like encrypted offload to accelerators and quantum-safe
                                                                                                cryptography. Combining this with open software and a robust ecosystem
                                                                                                helps customers:
                                                                                                • Protect enterprise data and models throughout the AI workflow.
                                                                                                • Ensure security and privacy from the edge to the cloud.
                                                                                                • Use legacy and emerging IT systems.
                                                                                                • Leverage the latest and greatest AI hardware.

                                                                                                The Rise & Threat of Generative AI
                                                                                                Despite its recent emergence, more than half of companies are estimated to
                                                                                                have GenAI workloads in production . These companies are investing in GenAI
                                                                                                use cases that span business functions—from drug discovery and risk
Table of Contents                                                                               management to real-time customer support and personalized marketing—
                                                                                                hoping to drive down costs, improve insights, and transform their businesses.
Executive Summary. .  .  .  .  .  .  .  .  .  .  .  .  .  .  . 1
                                                                                                Many companies, especially large enterprises, could unlock significant value
Introducing Confidential AI. .  .  .  .  .  . 2                                                 from their vast data estates by enabling more effective and accurate AI with
Threats to AI.  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  . 3              methods like fine-tuning and augmented retrieval. In the GenAI era, data will
                                                                                                serve as a competitive moat.
Enabling Confidential AI
at Scale .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  . 4   However, security risks, data silos, and compliance concerns limit companies’
                                                                                                ability to leverage these data and capitalize on their competitive advantage. As
Confidential Computing:                                                                         an emerging technology, GenAI introduces new security and privacy risks that
The Foundation for Secure                                                                       companies must navigate, from long-standing concerns like data theft to novel
AI Innovation .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  . 6                issues like hallucinations, prompt injections, and data poisoning.
White Paper | Confidential Computing: Powering the Next Generation of Trusted AI                                                                                                2



Failure to mitigate these risks could cause meaningful                                     When applied to AI workloads, Intel’s Confidential
reputational, financial, and operational damage, as well as                                Computing products help companies overcome the
the opportunity cost of missed transformations.                                            security and privacy concerns that inhibit them from
Recognizing these potential impacts, companies cite                                        extracting value from their data and GenAI. These
security and privacy concerns as a leading obstacle to                                     benefits extend from the edge to the cloud and support
deploying GenAI use cases.                                                                 data stores—new and old—with the hardware required for
                                                                                           the job.
In his blog on Creating a Foundation for End-to-End AI
Security Solutions, Jesse Schrater points out that AI is
transforming both the scale and predictability of data-                                                                    Edge Server App
driven decision-making. Where once we had clear control                                                                     Workload Connector
over inputs and logic, we now face vast, unstructured data
sources and non-deterministic models that evolve in ways
we can’t fully predict or audit. Traditional security                                                                        Intel TDX   Intel TDX

approaches—like static defenses and perimeter controls—
are no longer sufficient. As AI logic operates across billions
of devices and cloud platforms, security strategies must
evolve to match its dynamic and opaque nature, ensuring
                                                                                            Edge Server App
innovation doesn’t outpace the ability to govern it.                                         Workload Connector


Introducing Confidential AI
                                                                                                                                                           Attestation Service
Intel’s Confidential AI capabilities arise from its Confidential                                Intel TDX   Intel TDX

Computing products, Intel® Trust Domain Extensions                                                  Edge Server

(Intel® TDX) and Intel® Software Guard Extensions (Intel®
SGX). These technologies use a hardware-based trusted
execution environment (TEE) to protect sensitive data and
applications from unauthorized access.                                                                                         Zero Trust
                                                                                                                               Exchange
Trusted Execution
  Environment
                                                     Isolation                             Figure 2. Intel TDX allows verification of end users and
                                                                                           cloud sources in a zero trust exchange
         Sensitive Data                   Trusted Execution Environment
                                          (TEE) separates sensitive data and
       Trusted Software                   code from underlying software,                   Every AI workload, whether in the cloud or on a device, can
                                          admins, and other cloud tenants                  benefit from a secure environment that is tailored to fit its
        Trusted Admins                                                                     specific needs. Intel's Confidential AI has the flexibility to
                                                                                           support the emerging “AI everywhere” world.
                                                     Veriﬁcation
                                                     (Attestation)                         1.      For deployments where offload accelerators are not
                                          Cryptographic conﬁrmation                                required (e.g., small inferencing models, RAG
                                          that TEE is genuine, correctly                           VectorDBs) or are impractical (e.g., TCO factors),
                                          conﬁgured, and software is                               CPUs with Intel TDX and Intel SGX support Intel®
                                          exactly as expected                                      Advanced Matrix Extensions (Intel® AMX)
                                                                                                   accelerations to improve AI performance.
     Untrusted Software                              Encryption                            2.      For deployments requiring an accelerator or GPU, Intel
                                                     and Control                                   is introducing Intel® TDX Connect1 to provide a secure
          Cloud Stack                                                                              channel for communicating directly with PCIe-
                                          Workload owner holds key to
                                          decrypt data, retaining control                          compliant accelerators from any vendor.
         Cloud Admins
                                          and preventing access by cloud
                                                                                           3.      As AI moves to the edge, Confidential Computing
                                          provider or other entities
                                                                                                   provides workload and platform verification
                                                                                                   (attestation) to support Zero Trust assurances
Figure 1. A Trusted Execution Environment prohibits
                                                                                                   for endpoints.
unknown and unwanted infiltration from unverified sources




1. As a stepping stone to the first phase, Intel supports the secure use of Nvidia accelerators using bounce buffers—a software-based solution that has some performance overhead
   but can provide core functionality ahead of availability of the full hardware-based and performant Intel TDX Connect.
White Paper | Confidential Computing: Powering the Next Generation of Trusted AI                                                    3



Threats to AI                                                          Mitigations:
                                                                       Confidential Computing helps defend against model
Security researchers and organizations, from the Open                  inversion attacks by enforcing a secure, attested execution
Worldwide Application Security Project (OWASP) to the                  environment for AI workloads. Within an Intel-based TEE,
National Institute of Standards and Technology (NIST),                 access to the model can be strictly controlled and
have documented the threats that GenAI systems face.                   monitored. A trusted, attested inference module can
Protecting these systems typically calls for a layered                 restrict the types of queries allowed, prevent excessive or
security approach, with Confidential Computing supporting              abnormal interaction patterns, and apply privacy-
risk mitigation efforts.                                               preserving techniques (like differential privacy or query
Data Theft / Disclosure:                                               throttling) before releasing responses. This containment is
GenAI models rely on vast datasets, which often include                designed to ensure that only verified software with a limited
sensitive or proprietary information—sometimes                         interface can interact with the model, dramatically reducing
inadvertently (e.g., camera images with faces, license                 the risk of data leakage or inversion.
plates, etc.). During model training or inference, this data           Intellectual Property Theft:
must be decrypted and loaded into system memory, making                Proprietary AI models represent a major investment in data
it vulnerable to attack if not properly secured. Threat actors         acquisition, engineering, compute, and domain expertise.
targeting these stages can potentially extract confidential            These models—whether foundation models, fine-tuned
inputs, outputs, or even model parameters, leading to                  LLMs, or specialized neural networks—are core intellectual
regulatory exposure, customer mistrust, Intellectual                   property. If exposed, they can be reverse-engineered,
Property (IP) theft, and reputational harm.                            cloned, or illicitly redistributed, enabling competitors to
                                                                       replicate capabilities without incurring the original cost,
                                                                       eroding competitive advantage, and undermining trust in
                                                                       AI deployment.
AI Model                                                                Proprietary                                Recreated
                                                                        AI Model                                    AI Model
                          Attacker



Mitigations:
                                                                                           Theft, Reverse-
Confidential Computing protects sensitive AI data by
                                                                                           Engineering, etc.
encrypting memory and isolating processing environments,
helping ensure data remains secure even while actively in              Mitigations:
use. This is especially critical across the AI pipeline—during         Confidential Computing helps defend against model theft
model training, fine-tuning, and inference—when raw data               by ensuring the model is processed only in an unencrypted
and intermediate representations are most exposed. By                  state within the protected memory space of an Intel-based
running AI workloads inside hardware-based Trusted                     TEE. This helps protect against direct memory scraping
Execution Environments (TEEs), organizations can                       and other privileged attacks during inference. For AI
safeguard proprietary models and private user data from                models deployed at the edge (e.g., on medical devices,
malicious actors, infrastructure administrators, or                    mobile endpoints, or industrial sensors), where physical and
compromised system components.                                         administrative controls are limited, running within a
Model Inversion Attacks:                                               Confidential Computing enclave significantly elevates the
These attacks exploit access to a machine learning model               security posture, approaching the assurance levels of
and its predictions to reconstruct sensitive elements from             secured data center environments. It also helps ensure that
the training data. In generative and predictive AI systems—            only attested and authorized code can access the model,
particularly in healthcare, finance, or personalized                   making model extraction significantly more difficult and
services—this could mean recovering private patient                    detectable.
records, biometric data, or other personally identifiable              Data Poisoning:
information. Attackers leverage the model’s learned                    In the training phase of AI development, attackers can
patterns to reverse-engineer inputs, making even                       tamper with datasets—injecting mislabeled, adversarial, or
seemingly benign API access a potential privacy risk.                  biased samples to corrupt the learning process. This can
Released                                                               lead to subtle but dangerous degradations in model
AI Model                                                               behavior, such as misdiagnosis in healthcare models,
                                                                       discriminatory outputs in hiring tools, or exploitable
                                                                       behaviors in autonomous systems. Poisoning can occur
                                                                       through compromised data pipelines, third-party data
                                                                       sources, or malicious insiders—especially in federated or
                                 Attacker       Recreated
                                               Sensitive Data          collaborative training environments.
White Paper | Confidential Computing: Powering the Next Generation of Trusted AI                                                      4


              AI Model                                                 are many paths to scale. Cloud-first data and analytics
                                                                       providers are playing a pivotal role in driving AI adoption.
                                                                       Major hyperscalers are already integrating Confidential AI
                                                                       services for data clean rooms, multi-party federated
                                                                       learning, confidential inferencing, and more. OEM and ISV
Corrupt                                      Compromised
                                                                       partners are integrating Confidential Computing into their
Dataset                                        Outcome
                                                                       platforms—whether through secure hardware, software
Mitigations:                                                           frameworks, or data-centric services—to enable integrity
Confidential Computing is designed to ensure that training             and confidentiality in solutions that accelerate the broader
data is processed only within attested, hardware-isolated              growth and trusted deployment of AI across industries.
environments, shielding it from tampering by malware,
rootkits, or even privileged insiders. This not only helps             Public Cloud
protect against zero-day exploits and system-level threats             Intel is working with its cloud partners to ensure that
but also supports data provenance, enabling models to be               technologies such as Intel TDX and Intel TDX Connect
trained only on verifiably unmodified inputs. When                     become ubiquitous across all types of cloud
combined with encryption at rest and in transit, Confidential          environments—public, private, hybrid, and multi-cloud.
Computing enables full-lifecycle protection for sensitive              For example, Google's adoption of Intel AMX and Intel TDX
training data, helping ensure integrity from data ingestion to         to drive accelerated confidential workloads that can also
model output.                                                          leverage Nvidia GPUs is now available on Google Cloud.
                                                                       Alibaba Cloud shows how to integrate Haystack from
Compliance Violations:                                                 Deepset into an Intel TDX instance to deliver a more secure
Industries such as healthcare, finance, and public services
                                                                       RAG solution.
face mounting regulatory pressure to ensure responsible AI
use, with frameworks like General Data Protection                      By embedding Confidential Computing at the core of AI
Regulation (GDPR), European Union (EU), Health Insurance               cloud infrastructure, Intel aims to:
Portability and Accountability Act (HIPAA), and others
                                                                       1.   Build Trust: Enhance trust and security for sensitive
enforcing strict controls on how personal and sensitive data
                                                                            AI workloads, allowing enterprises to innovate
is processed, especially in AI systems. GenAI in particular
                                                                            with confidence.
introduces complex risks around data leakage, lack of
transparency, and unexplainable decision-making. If a                  2.   Streamline Integration: Simplify adoption by ensuring
GenAI system inadvertently trains on or reveals protected                   seamless integration of Intel TDX technologies into AI
data or operates without verifiable controls, organizations                 development and deployment pipelines.
may be exposed to severe fines, legal liability, and
reputational damage.                                                   3.   Enable More Secure Migration: Accelerate AI workload
                                                                            migration to secure cloud environments, enabling
          AI Model                                                          broader enterprise adoption of cloud-native AI.
                                                                       4.   Expand Partnerships: Strengthen ecosystem
Violation
                                                                            partnerships by collaborating with ISVs, systems
                                                                            integrators, and service providers to optimize
                                        Exposure to                         Confidential Computing solutions across the cloud
                         Violation
                                     Fines, Liability, etc.                 AI stack.
                                                                       Through this focus, Intel and its partners will help
Mitigations:                                                           organizations unlock new AI capabilities while safeguarding
Confidential Computing offers a powerful foundation to                 data, models, and intellectual property—driving the next
enhance compliance in AI by enabling attested execution                wave of secure, scalable AI innovation.
environments, where only cryptographically verified code
can access sensitive data or models. These attestations
serve as machine-generated, tamper-proof evidence of
data handling practices, increasingly satisfying
requirements for data-in-use protection, software
integrity, and provenance tracing. For Generative AI
workloads—whether in training, fine-tuning, or inference—
this helps ensure sensitive data is processed only within
verified and isolated environments, supporting Zero
Trust principles and aligning with evolving audit and
governance frameworks.

Enabling Confidential AI at Scale
As AI platform solutions and services continue to expand
across cloud, edge, and on-premises environments, there
White Paper | Confidential Computing: Powering the Next Generation of Trusted AI                                                      5




Advancing Confidential AI in the Enterprise                            Through these strategic initiatives, Intel is advancing the
Leading OEMs are investing in building Confidential AI                 next generation of secure, scalable AI solutions with its
appliances, designed to meet the growing demand for                    OEM partners, helping enterprises accelerate innovation
high-performance, secure AI infrastructure in sectors such             while protecting what matters most in any environment.
as healthcare, finance, and government. These appliances
are purpose-built for enterprises that must process                    Empowering the ISV Ecosystem
sensitive data within trusted, on-premises environments.               The growing ISV ecosystem plays a vital role in expanding
                                                                       the adoption of secure AI solutions across industries.
Intel's OEM partners are increasingly recognizing the value            Companies specializing in data security, confidential cloud
of Intel-based Confidential Computing technologies as a                services, and AI infrastructure are increasingly building
critical enhancement for large-scale deployments,                      on-premises and cloud-based Confidential AI solutions,
particularly in highly regulated industries.                           driven by their customers’ demands for greater data privacy
                                                                       and regulatory compliance.
One example of innovation in this space is the development
of PrivateGPT appliances—secure, enterprise-grade AI                   Leading ISVs across the AI pipeline—from security
platforms that enable organizations to build, fine-tune, and           providers to vector database companies, MLOps platforms,
deploy GenAI models on sensitive proprietary data without              and model developers—are building the tools required for
exposing that data outside their trusted environments.                 enterprises to develop, deploy, and manage GenAI
These Confidential AI solutions, powered by Intel                      capabilities securely. By engaging with these ecosystem
technologies, enable organizations to unlock the full                  participants, Intel is helping to enhance the security posture
potential of AI while maintaining control over their most              throughout the AI lifecycle and accelerate adoption of
valuable information assets.                                           Confidential Computing technologies.
To support this growing opportunity, Intel is focused on two           To support and strengthen this ecosystem, Intel is
key areas:                                                             focused on:
1.   Empowering OEM Confidential AI Stacks: Intel is                   1.   Partner Engagement: Intel is collaborating early with
     enabling its OEM partners to integrate Intel’s                         key ISV partners by providing early access to Intel
     Confidential Computing technologies into their                         hardware, technical enablement, and architectural
     Confidential AI solutions, helping enterprises                         guidance to drive the integration of Intel Confidential
     confidently adopt secure AI platforms tailored to                      Computing technologies into their AI offerings.
     their needs.                                                           Privatemode.ai enables enterprises to use large
                                                                            language models like Llama 3 securely by running the
2.   Driving CPU-Optimized GenAI Solutions: Intel is also
                                                                            entire inference process—inputs, models, and
     collaborating with OEM partners to develop CPU-only
                                                                            outputs—inside a TEE. This Confidential Computing
     GenAI appliances that deliver strong price-
                                                                            approach helps ensure that sensitive enterprise data,
     performance advantages, making secure generative AI
                                                                            such as customer records or internal documents,
     accessible to small and medium-sized enterprises. Dell
                                                                            remains encrypted and isolated, even while in use,
     is leading the way, showing how Intel TDX helps protect
                                                                            shielding it from the cloud provider, infrastructure
     AI workloads when running on Intel® Xeon® processor-
                                                                            admins, and external threats. The model itself is also
     based servers.
 White Paper | Confidential Computing: Powering the Next Generation of Trusted AI                                                                                                          6


       increasingly protected from theft or tampering, and                                       By fostering deep technical partnerships and empowering
       remote attestation provides cryptographic proof that                                      the next generation of AI-focused ISVs, Intel is positioning
       only trusted, verified code is running. For enterprises,                                  Confidential Computing as a critical enabler for secure,
       this means they can deploy GenAI solutions—such as                                        trusted AI innovation—helping customers unlock the full
       secure copilots, document summarizers, or analytics                                       value of AI at scale while maintaining strict control over their
       tools—with increased confidence in their ability to                                       sensitive data.
       maintain data confidentiality, meet regulatory
       requirements, and support data sovereignty across                                         Confidential Computing: The Foundation for
       public and hybrid clouds.                                                                 Secure AI Innovation
 2.    Joint Innovation and Market Alignment: Intel is working                                   In a world where AI is rapidly becoming pervasive, the
       closely with strategic partners to develop joint go-to-                                   importance of Confidential Computing for improved
       market initiatives, helping ensure that Confidential                                      security cannot be overstated. As organizations deploy AI
       Computing solutions are well aligned to emerging                                          across internal and external environments, protecting
       industry needs and AI use cases. Intel is collaborating                                   sensitive data at all stages—in transit, at rest, and in use—is
       with Fortanix on solutions like Armet AI, which                                           no longer optional... it is essential. In many sensitive data
       combines Intel TDX with Fortanix's secure data                                            scenarios, it could be the catalyst to unlock data silos that
       platform to help protect sensitive data and models in                                     open huge digital transformations.
       AI pipelines—enabling regulated industries to adopt
       Confidential AI with greater confidence                                                   Intel’s Confidential Computing portfolio provides
       and compliance.                                                                           comprehensive solutions to secure AI wherever it resides. It
                                                                                                 addresses the threats that GenAI introduces or
 3.    Showcasing Industry-Specific Solutions: Intel is                                          exacerbates, giving organizations increased confidence to
       highlighting real-world examples and industry-specific                                    accelerate their AI journeys and unlock the full value of their
       deployments where Intel’s Confidential Computing                                          proprietary data. This portfolio is powered by open
       technologies help ISVs deliver differentiated, Secure                                     software and a vibrant ecosystem of software, cloud,
       and Trusted AI solutions to their customers. EQTY Lab                                     and device partners that extend its reach far beyond
       integrates Intel TDX to build privacy-preserving AI                                       Intel’s walls.
       infrastructure that enables enterprises to collaborate
       on sensitive data without sacrificing control or                                          The future of Confidential Computing for AI workloads lies
       confidentiality. Their platform is designed around                                        in its ability to provide businesses with the trusted
       verifiable trust, ensuring that AI models operate only                                    foundation they need to innovate without compromise.
       within attested environments, with strict enforcement                                     With that strong foundation in place, Intel is advancing the
       of data usage policies. This approach empowers                                            Confidential Computing ecosystem to meet the evolving
       customers to adopt AI in high-stakes contexts                                             demands of AI—today and into the future.
       where transparency, integrity, and data sovereignty
       are essential.



      Look for Intel-based Confidential Computing instances in Cloud Service Provider and server vendor offerings today.
      Contact Intel's many ecosystem partners for value-added solutions, or visit intel.com/confidentialcomputing for
      more information on how Intel is designing Confidential AI to be secure, scalable, and trusted by design.




 Legal Notices and Disclaimer
 Intel technologies may require enabled hardware, software, or service activation.
 No product or component can be absolutely secure.
 Your costs and results may vary.
 Intel does not control or audit third-party data. You should consult other sources to evaluate accuracy.
 All product plans and roadmaps are subject to change without notice.
 Intel disclaims all express and implied warranties, including without limitation, the implied warranties of merchantability, fitness for a particular purpose, and non-infringement, as well as
 any warranty arising from course of performance, course of dealing, or usage in trade.
 © Intel Corporation. Intel, the Intel logo, and other Intel marks are trademarks of Intel Corporation or its subsidiaries. Other names and brands may be claimed as the property of others.




i. IDC 2024 Global GenAI Technology Trends Report
ii. Confidential AI Survey, Q3 2024; IDC 2024 Global GenAI Technology Trends Report
iii. OWASP Top 10 for LLM Applications 2025; NIST Trustworthy and Responsible AI NIST AI 100-2e2025
