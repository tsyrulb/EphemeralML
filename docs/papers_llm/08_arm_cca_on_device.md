                                           An Early Experience with Confidential Computing Architecture for On-Device
                                                                       Model Protection

                                                     Sina Abdollahi∗ , Mohammad Maheri∗ , Sandra Siby† , Marios Kogias∗ , Hamed Haddadi∗
                                                                         ∗ Imperial College London          † New York University Abu Dhabi



                                         Abstract—Deploying machine learning (ML) models on user                 Environment, or REE [6]). Deploying models in a TEE
                                         devices can improve privacy (by keeping data local) and                 mitigates privacy-stealing attacks from REE-based adver-
                                         reduce inference latency. Trusted Execution Environments                saries: even if the REE is compromised, the adversary is
                                         (TEEs) are a practical solution for protecting proprietary              limited to black-box access to the model, whereas models
                                         models, yet existing TEE solutions have architectural con-              deployed in the REE are exposed to white-box attacks.
                                                                                                                     On the other hand, using TEEs on end devices face
arXiv:2504.08508v1 [cs.CR] 11 Apr 2025




                                         straints that hinder on-device model deployment. Arm Con-
                                         fidential Computing Architecture (CCA), a new Arm exten-                security and functionality challenges. While Intel Soft-
                                         sion, addresses several of these limitations and shows promise          ware Guard Extensions (SGX) has been deprecated on
                                         as a secure platform for on-device ML. In this paper, we                end-user devices [7], Arm’s TEE—commonly known as
                                         evaluate the performance–privacy trade-offs of deploying                TrustZone—remains a widely adopted on-device solution,
                                         models within CCA, highlighting its potential to enable                 implemented in various mobile platforms (e.g., Qual-
                                         confidential and efficient ML applications. Our evaluations             comm, Trustonic). However, as Cerdeira et al. [8] showed,
                                         show that CCA can achieve an overhead of, at most, 22% in               TrustZone has been the target of high-impact attacks due
                                         running models of different sizes and applications, including           to its security vulnerabilities. The high privilege level of
                                         image classification, voice recognition, and chat assistants.           TrustZone, has led vendors to impose functional restric-
                                         This performance overhead comes with privacy benefits, for              tions in an effort to reduce the attack surface, restrictions
                                         example, our framework can successfully protect the model
                                                                                                                 such as lack of support for GPU accessing [9], and small
                                                                                                                 memory size (32MB for OP-TEE) [10].
                                         against membership inference attack by 8.3% reduction in
                                                                                                                     To overcome these limitations, several solutions have
                                         the adversary’s success rate. To support further research and
                                                                                                                 proposed partitioning models and executing only the more
                                         early adoption, we make our code and methodology publicly
                                                                                                                 sensitive components within TEEs [11], [12]. These ap-
                                         available.
                                                                                                                 proaches aim to provide near black-box security without
                                                                                                                 placing the entire model inside the TEE. However, Zhang
                                         1. Introduction                                                         et al. [13] demonstrate that such solutions remain vulner-
                                                                                                                 able to privacy-stealing attacks and are not as secure as
                                              Machine-learning (ML) models are increasingly being                commonly assumed. Even partial model weights can leak
                                         deployed on edge devices for various purposes such as                   private information about the training dataset, particularly
                                         health monitoring, anomaly detection, face recognition,                 when combined with publicly available resources (e.g.,
                                         voice assistants etc. Running models locally can provide                similar datasets or pre-trained models). Therefore, deploy-
                                         low-latency services to users without the need for sending              ing the entire model within the TEE boundary remains the
                                         data to an external entity. As end-users typically lack                 most effective strategy for protecting it against privacy
                                         the resources required to train a model, they prefer to                 attacks.
                                         utilize a pre-trained, reliable model owned by a third party                Arm Confidential Compute Architecture (CCA) [14]
                                         for inference and, potentially, personalization. The model              is a key component of the Armv9-A architecture that is
                                         owner, having invested significant resources in training the            expected to be available on Arm devices. Arm CCA allows
                                         model, requires robust security assurances to safeguard the             the creation of special virtual machines called realm,
                                         model’s integrity and usage. Without these guarantees, the              orthogonal to the already existing TrustZone. Realm is
                                         owner may not be willing to deploy the model on end                     de-privileged as it has virtualized access to the resources,
                                         devices.                                                                and it is TEE because it has protection against REE actors.
                                              Various solutions have been proposed for model pro-                Realm creation and runtime are supported by hardware-
                                         tection on the edge. Cryptographic techniques such as ho-               backed attestation services which can provide enough
                                         momorphic encryption (HE) [1]–[3] or secure multiparty                  evidence for a relying party (e.g., model provider) about
                                         communication (SMC) [4], [5] are hindered by compu-                     the trustworthiness of the realm. Compared to TrustZone,
                                         tational and communication overheads, while the use of                  CCA benefits from a more flexible memory allocation
                                         trusted execution environments (TEEs) is considered a                   scheme.1 The CCA features seem promising for on-device
                                         more efficient approach. A TEE is an environment that                   model deployment. Given that Arm is the dominant archi-
                                         uses hardware-enforced mechanisms to protect memory
                                         and execution from the operating system (OS) and its ap-                   1. TrustZone enforces isolation using an Address Space Controller
                                         plication layer (collectively known as the Rich Execution               (TZASC) and bus-level protection, requiring coarse-grained changes to
                                                                                                                 memory regions. In contrast, CCA uses standard page tables and the
                                         Accepted to the 8th Workshop on System Software for Trusted Execution   Memory Management Unit (MMU) to enforce isolation, allowing for
                                         (SysTEX 2025).                                                          fine-grained and dynamic memory management.
                                                                TABLE 1: Memory access rules applied by granule pro-
                                                                tection check (GPC)
                                                                 Security State   Normal PAS     Secure PAS    Realm PAS     Root PAS
                                                                 Normal              Yes             No            No           No
                                                                 Secure              Yes             Yes           No           No
                                                                 Realm               Yes             No           Yes           No
                                                                 Root                Yes             Yes          Yes          Yes



                                                                2.1. Arm Confidential Compute Architecture

                                                                    Arm CCA [14] is a series of hardware and software
                                                                architecture extensions that enhances Armv9-A support
                                                                for confidential computing. As shown in Figure 1, Arm
                                                                CCA, introduces four worlds3 : root, realm, secure, and
Figure 1: Arm CCA software architecture. The hypervisor         normal world (a.k.a., non-secure world). To enforce iso-
allocates resources to realms but cannot access those           lation between the worlds, CCA introduces a mechanism
resources, due to isolation boundaries between the realm        called granule protection check (GPC). Any memory ac-
and the normal world                                            cess request succeeds only if the requester state (e.g.,
                                                                processor state) and the memory’s state both comply with
                                                                the rules defined in Table 1. Particularly, the root world
tecture in mobile and edge devices, we anticipate CCA’s         state can access the physical address space (PAS) of all
widespread deployment in the near future.                       the other worlds while the realm and secure worlds state
Motivation. Inspired by (1) the limitations of existing         have access to the normal PAS, but they cannot access
TEE solutions, (2) vulnerabilities in current model par-        each other’s PAS. The normal world (NW) state cannot
titioning strategies, and (3) the key features of Arm CCA,      access the PAS of the other worlds. Arm architecture
this work introduces and evaluates a framework for de-          allows different exception levels (EL) to exist, from EL3
ploying on-device models within Arm CCA. We use the             (the highest privilege) to EL0 (the lowest privilege).
latest tools and plugins provided by Arm to simulate and        Software architecture. Figure 1 shows the software archi-
trace Arm CCA behavior in running ML workloads. We              tecture of Arm CCA. The Monitor is the highest privileged
do not employ partitioning strategies, ensuring that the        firmware in the system responsible for initially booting all
entire model remains protected from REE actors. Our find-       EL2 firmware/software, managing the GPC, and context
ings and evaluation results can be useful to support further    switching between different worlds. The normal world
research and early adoption, prior to the widespread adop-      stack consists of a hypervisor operating at NW-EL2, vir-
tion of CCA on end devices.                                     tual machines running at EL1 and EL0 and user-space
     Our contributions are as follows:                          apps running at EL0. The hypervisor is responsible for
                                                                managing all resources (e.g., CPU and memory) in the
    •   We define a basic framework for on-device model         system. The realm world stack consists of a lightweight
        deployment within Arm CCA and use the lat-              firmware known as Realm Management Monitor (RMM)
        est tools, software, and firmware to simulate the       which mediates resource allocation of realm VMs, and
        framework.                                              realm VMs (or simply realms) running at EL1 and EL0.
    •   We evaluate the framework for models of differ-         RMM enforces isolation boundaries between the hyper-
        ent sizes and applications, all showing acceptable      visor and the realm VMs, making realm resources (e.g.,
        overhead (22% in the worst case).                       memory pages of the realm VM) inaccessible for the hy-
    •   To showcase the security gain of the framework,         pervisor. The RMM is also able to generate an attestation
        we implement a membership inference attack on           report for the realm VM. This report keeps necessary
        the models, showing that running models within a        information about the initial content of the realm as well
        realm, on average, provides an 8.3% decrease in         as the firmware (RMM and Monitor) in the system [15],
        the success rate of membership inference attacks        [16].
        against the training dataset.
    •   We make all our code and framework openly
        available and will maintain it to benefit early-stage   2.2. Realm Overhead
        adoption of CCA software products2 .
                                                                    Handling exceptions4 is more complex for a realm
                                                                VM, compared to a normal world VM. For a normal world
2. Background                                                   VM, every exception is directly received and handled by
                                                                the hypervisor, while for a realm VM, the RMM is initially
    In this section, we first provide a brief overview of       responsible for handling the exception and, if necessary,
Arm CCA (Section 2.1) and why it comes with overhead            forwarding it to the hypervisor. This complexity increases
(Section 2.2). We also discuss the possible choices of          the overhead of running a workload within realm. Two
evaluating CCA (Section 2.3). Finally, in Section 2.4,
we introduce a privacy-stealing attack commonly used in           3. In some references, execution environment is used instead of world,
                                                                however in this work they are interchangeable.
security evaluations of ML systems.                               4. In Arm architecture, exceptions are conditions or system events that
                                                                require action by privileged software [17]. Notably, interrupts triggered
  2. https://github.com/comet-cc/CCA-Evaluation                 by virtual devices (e.g., virtual timer) are a type of exception.
notable sources of exceptions are the hypervisor’s timer         3.1. System Model
interrupt (timer at NW-EL2) and the realm’s timer inter-
rupts (timer at Realm-EL1), both necessary for process               As illustrated in Figure 2, the system involves three
scheduling within the two kernels. Each time these timers        parties: model providers, clients, and a trusted verifier.
are acknowledged by the processor, an exit from the realm        A model provider is an entity responsible for training
occurs, which requires handling by the hypervisor. In            and deploying ML models on end-devices for various
Section 4.2 and Appendix B we compare the runtime                tasks. These models, along with their training datasets,
execution and I/O operation between a realm and a NW             are considered intellectual property and must be protected
VM.                                                              from unauthorized access by malicious users and other
                                                                 model providers. The client is an end-device, such as a
2.3. CCA Evaluation Platforms                                    smartphone or an IoT gateway, which supports Arm CCA.
                                                                 Clients host a wide variety of applications within their
    At the time of writing, there is no hardware compatible      REE that may require machine learning services, such as
with the CCA specification. However, there are software          facial recognition, voice detection, or chat assistants. The
that emulates the behavior of a CCA-compatible device.           trusted verifier is responsible for providing realm images.
Linaro’s QEMU [18] can be used to boot and run the               A realm image includes a complete stack for a virtual
CCA software stack [19]. Fixed Virtual Platform (FVP) is         machine, encompassing an operating system, user-space
the official software released by Arm, compatible with the       libraries, and applications necessary for running the model
CCA specification [20], [21]. FVP provides useful plugins        within the realm.
and tools which, combined, provide detailed information
about the behavior of CCA. Devlore [22] used QEMU,               3.2. Threat Model
but other works have used FVP in their evaluation as
functional prototype [23], [24] and also performance pro-            We assume that model providers and clients are two
totype [25]–[27]. We utilize FVP5 for the evaluation. In         mutually distrusting entities, but they both trust the images
Appendix A, we describe how FVP can be set up with               offered by the trusted verifier. Clients may attempt to
plugins and tracing tools to measure realm’s behavior.           maliciously extract information about the model’s weights
Furthermore, we explain the accuracy of FVP and other            and training data. Both the Monitor and the RMM are
possible options to evaluate CCA. It is important to note        considered trustworthy due to their small codebase, and
that neither FVP nor QEMU is designed to provide per-            formal verification in the case of the RMM [29], [30].
formance predictions, and any evaluation based on these          However, the NW stack is untrusted as it is large and com-
tools should be regarded as preliminary and approximate.         plex, containing unverified user-space applications, third-
                                                                 party libraries, and drivers. An adversary could exploit
                                                                 these vulnerabilities to compromise the entire NW. Arm
2.4. Membership Inference Attack
                                                                 CCA, by default, does not provide availability guarantees
                                                                 regarding runtime execution and memory of realm. How-
    Membership inference attacks (MIA) are a class of            ever, we assume that the hypervisor allocates sufficient
attacks in which an adversary tries to determine whether         CPU time and memory to the realm, allowing it to ef-
a particular data point was a part of the training set or not.   fectively load the model and perform inference6 . Physical
These attacks have been widely used in the literature to         and side-channel attacks are also significant threats to the
assess how much a system “leaks” information about the           deployment of the device model [31], [32]. However, there
training dataset [11]–[13]. In a typical attack setting [13],    are considered out of scope and the hardware is trusted.
[28], an adversary has access to a shadow dataset which
is statistically similar to the target model’s dataset. This
dataset is then used to train a shadow model and an attack       3.3. Model Deployment Pipeline
model (a binary classifier). Finally, to determine whether
a data sample is a member of the target model’s training             Figure 2 shows an overview of our framework. In the
dataset, the sample is fed to the target model, and the          following, we provide a description of the various steps
posteriors and the predicted label (transformed to a binary      involved in deploying the model within a realm.
indicator on whether the prediction is correct) are fed to       Realm setup. A NW app starts the process by obtaining
the attack model. Moreover, an adversary with white-box          a publicly-available and verified realm image from the
access can enhance the attack’s accuracy by leveraging           trusted verifier (Step 1 in Figure 2). The realm creation is
additional model information, such as classification loss        done by a collaboration among a virtual machine manager
and sample gradients (see [13], [28] for details). We use        (VMM) at NW-EL0, the hypervisor, and the RMM (Step
this attack in Section 4.3 to show the privacy protection        2). After populating the realm memory, the hypervisor
of our framework.                                                sends the activation command to the RMM. Once the
                                                                 realm is activated, it can receive CPU time, and the
                                                                 hypervisor is no longer able populate new content into
3. Framework Architecture                                        the realm’s address space.
    In this section, we describe a basic framework to            Model initialization. After realm’s kernel is booted,
deploy on-device models within CCA. We follow the                the realm establishes a TLS connection with the model
system model introduced by [27].                                    6. Altering these assumptions does not impact the security of the
                                                                 model, it only affects the quality of the ML service experienced by
  5. More specifically, we use FVP Base RevC2xAEMvA 11.25 15     the NW app.
                                                              4.1. Experimental Setup

                                                                  In this section, we describe the experimental setup
                                                              used to evaluate our framework. We compare our frame-
                                                              work with a baseline scenario, involving deploying model
                                                              within a normal world VM. We use FVP to report the
                                                              overhead of our framework in comparison to the baseline.
                                                              FVP is instruction-accurate, that is, it accurately models
                                                              the instruction-level behavior of a real processor that sup-
                                                              ports CCA [21], [33]. However, it does not effectively cap-
                                                              ture certain micro-architectural behaviors (e.g., caching
Figure 2: Overview of the steps required for running a        and memory accesses), which makes cycle-accurate and
ML model on the client edge device. We show a simplified      timing-based measurements unreliable [33]. While we use
view of the normal and realm worlds within the client. The    FVP to report the number of instructions executed by
client’s steps are (1) obtaining realm image from verifier    the FVP’s processor core, these measurements should be
(2) creating and activating a realm VM (3) establishing       regarded as preliminary estimations. We do not claim that
connection with provider (4) realm attestation (5) obtain-    they represent the actual performance overhead on real
ing model from provider (6) announcing model readiness        CCA hardware. In Appendix A, we provide extensive
to normal world (7) running inference (8) performing          information on how to set FVP in conjunction with trac-
model updates.                                                ing tools to accurately measure number of instructions
                                                              executed by the FVP’s core. We also use Shrinkwrap
provider (Step 3). Later, the realm sends an attestation      [34], a tool that simplifies the building and execution
request to the RMM and in return, the RMM sends the           of firmware/software on FVP. Shrinkwrap automatically
attestation report to the realm, which is forwarded to the    downloads and builds necessary firmware based on the
model provider (step 4). The model provider can now use       given configuration files. More information on software
the attestation report to verify the content of the realm     and firmware version we used for the evaluation is pro-
and decide whether it can trust the realm or not. On          vided in Appendix A.
verification, the model provider sends the model to the       Privacy protection. As discussed in the threat model
realm via the TLS connection (Step 5).                        (Section 3.2), all software in the normal world is con-
Inference. The realm’s kernel includes a virtio-9p driver,    sidered untrusted. Consequently, in the baseline sce-
which is used to establish a file-system-based shared         nario—where the model runs within a normal world
memory with the NW app. After receipt of the model,           VM—the model is entirely exposed to potential adver-
the realm announces its ability to respond to inference       saries. An adversary with this level of white-box access
queries to the NW app (Step 6). Later, the NW app sends       can launch privacy-stealing attacks to infer information
input data to the realm, the realm feeds it into the model,   about the model’s training dataset. In contrast, our frame-
obtains the inference, and writes the output back to the      work protects the model by executing it within realm,
shared file system so that the NW app can read it (Step       effectively concealing its weights from NW adversaries.
7).                                                           Specifically, our framework restricts the adversary’s access
                                                              to the model to a black-box setting, where only query
Service maintenance. In addition to performing infer-
                                                              access is allowed. In Section 4.3, we demonstrate the
ence, the framework must also handle other maintenance
                                                              resulting privacy advantages by evaluating both white-box
operations. For example, a model provider might set us-
                                                              and black-box membership inference attacks.
age limits—such as a validity period or maximum in-
ferences—by embedding this functionality in the realm         Models. Table 2 shows an overview of the models and
image. Once these limits are reached, the realm calls the     settings used in the evaluation. We choose models of var-
hypervisor to terminate and release its memory. The realm     ied sizes and types for typical on-device tasks like image
can also periodically query the model provider for updates    classification, speech recognition, and chat assistants. For
on the model (step 8).                                        each model, an appropriate VM size is chosen, which is
Integration with mobile devices. Our framework can be         enough for the run-time progress of inference. The size of
adapted for deployment on mobile devices. A potential         the virtual machine depends mainly on the use of inference
setup involves a hypervisor supporting CCA running at         code, the size of the model, and the size of dynamic
EL2, with Android at EL1 and user applications at EL0. In     libraries required for each model.
this configuration, while Android remains responsible for
managing applications running at EL0, the hypervisor can      4.2. Inference Overhead
create and manage Realm VMs, enabling secure execution
environments for sensitive models.                                In order to evaluate the overhead of our framework, we
                                                              perform an evaluation with two scenarios. In the baseline
4. Evaluation                                                 scenario, the model and the code are stored in a NW VM.
                                                              In the second scenario, the model and code are stored in
   In this section, we evaluate and compare our frame-        a realm VM. In both scenarios, a file system-based data
work against a baseline scenario in which the model is        sharing is established between the VM and the NW app,
deployed within a NW VM. We show the computational            allowing the NW app to send input queries and receive
overhead and privacy benefit of our framework.                inference outputs. In order to get more insights about the
TABLE 2: Experimental settings used in the evaluation. The VM size depends on runtime memory use of inference
code, size of model, and size of dynamic libraries required for each model.
 Experimental Setting                     Model                      Model Size (MB)           Library (API)         Input Format         VM size (MB)
         1                               AlexNet                             9             TensorFlow Lite (C++)         .bmp                 300
         2                      MobileNet v1 1.0 224 [35]                   16             TensorFlow Lite (C++)         .bmp                 400
         3                              ResNet18                           44              TensorFlow Lite (C++)         .bmp                 450
         4                    Inception v3 2016 08 28 [36]                  95                TensorFlow (C++)            .jpg               1750
         5                                VGG                              261                TensorFlow (C++)           .wav                3650
         6                              GPT2 [37]                          177              llama.cpp [38] (C++)          text                900
         7                            GPT2-large [39]                      898              llama.cpp [38] (C++)          text               1800
         8                    TinyLlama-1.1B-Chat-v0.5 [40]               1169              llama.cpp [38] (C++)          text               2000

TABLE 3: Mean (standard deviation) of instructions executed per inference service. Each experimental setting is
described in Table 2.
           Model Initialization (106 )        Read Input (106 )       Inference Computation (106 )       Write Output (106 )              Total (106 )
 Setting
           R VM     NW VM        Ovh     R VM     NW VM        Ovh     R VM     NW VM       Ovh      R VM     NW VM       Ovh    R VM        NW VM       Ovh
   1         1.6       1.2       33%      0.6        0.3     100%        98.0       82.0    19%        1.1       0.5     120%     105.9        87.8      20%
   2         1.7       1.2       41%      4.7        1.1     100%       335.4      278.9    20%        0.7       0.3     133%     351.8        289.3     21%
   3         2.1       1.6       31%      0.6        0.3     100%       418.2      344.0    21%        0.9       0.4     125%     442.8        363.2     20%
   4        397.9     333.4      19%      2.8        1.8       55%     7663.8     6382.8    20%        4.6       3.5      31%    8717.2       7201.1     21%
   5        345.1     295.8      16%      1.8        1.1       63%     6365.7     5420.7    17%       0.15      0.09      66%    6713.2       5717.9     17%
   6       1039.1     821.9      26%      2.7        1.8       50%    12036.6     9858.7    22%       0.11      0.04      75%   13144.9      10726.3     22%
   7       2653.6    2158.5      22%      2.7        1.8       50%    73603.1    59870.6    22%       0.07      0.04      75%   76412.3      62156.4     22%
   8       2784.9    2312.1      20%      2.6        1.8       44%    94480.0    79452.7    18%       0.07      0.04      75%   97433.3      81905.6     18%



inference service, we divide the service into four stages                         figures as overheads that would be replicated on actual
and measure each one separately, (1) model initialization,                        CCA hardware.
which involves loading the model into memory allocated
by the inference code, (2) getting input from the NW app                          4.3. Membership Inference Attack
and storing it in the inference code memory (3) inference
computation, which refers to local computations within                                To demonstrate the security benefits of our framework,
the VM to obtain the output, and (4) writing the output                           we conduct both white-box and black-box membership
back to the NW. For each experiment in both scenarios,                            inference attacks on two models (experimental setting
we instantiate five VMs and perform five inferences per                            1 and 3 in Table 2). We adopt the MIA proposed in
VM, yielding a total of 25 repetitions per configuration.                         [13], using the same settings and hyper-parameters (e.g.,
We report the mean values, however standard deviations                            learning rate, number of epochs, etc). In this attack, the
are omitted as they are consistently below 10% in all                             adversary has access to a shadow dataset drawn from the
experiments.                                                                      same distribution as the training dataset. The adversary
     Table 3 shows the results of our evaluations. As il-                         then uses the shadow dataset to train a binary classifier
lustrated, the total overhead of inference service within                         that infers membership in the target training dataset (see
the realm is moderate, ranging from 17% to 22%. Model                             Section 2.4 for details). While the default assumption in
initialization overhead varies between 16% to 41% de-                             [13] is that the shadow dataset size matches that of the
pending on the API used for inference. The highest num-                           training dataset, this assumption may not be realistic in
bers are within experiments 1 , 2 , and 3 , all using the                         all practical scenarios. To account for this, we experiment
TFlite API. On the other hand, overhead of read input and                         with three different ratios between the training dataset
write output are between 44% and 100%, and 31% and                                and shadow dataset sizes. Specifically, we fix the size of
133%, respectively, showing considerably bigger overhead                          the training dataset across all scenarios and reduce the
in I/O-involved operations within realm. The variation in                         shadow dataset size to 1/4 and 1/8 of the training dataset
input read overhead is primarily due to differences in input                      size. We conduct these experiments using two models and
size across models, while the variation in output write                           three different datasets. The results, presented in Table 4,
overhead is attributed to the number of output classes                            shows that the adversary’s success rate decreases by an
and the format in which outputs are returned to the NW                            average of 12.4% and 4.2% for AlexNet and ResNet18,
app. As explained in Section 2.2, the main contributor                            respectively (8.3% reduction on average). These findings
to these overheads is the increased complexity of ex-                             are consistent with similar observations in [28]. Notably,
ception handling in the realm. Although I/O operations                            the gap between the adversary’s success rates in the two
are relatively expensive in this setting, they represent                          settings grows as the number of output classes increases.
only a small portion of the total computation and do                              The gap is larger for CIFAR100 (100 output classes) than
not significantly affect the overall inference performance.                       for CIFAR10 (10 output classes) and CelebA (configured
We also perform another experiment to see how much                                for 32 output classes in our evaluation).
each entity is responsible for the overhead of inference
computation and report the results in Appendix B. Finally,                        5. Discussion
it is important to note that these results represent only an
initial approximation, based on the number of instructions                        Realm device assignment. Device assignment is one of
executed by the simulator’s core. We do not report these                          the planned future enhancements for CCA [41], and it
TABLE 4: Adversary’s success rate in the membership inference attack. NW: Model is deployed within NW, giving the
adversary white-box access to the model, RW: Model is deployed within realm world, giving the adversary black-box
(label-only) access to the model. R is the ratio between the size of shadow dataset and the size of training dataset
                                     R=1                      R = 1/4                  R = 1/8
     Model     Deployment                                                                               Total (Average)
                            CF10    CF100   CelebA    CF10    CF100 CelebA     CF10    CF100 CelebA
                  NW        71.8      84     84.9     65.4     83.9   82.4      57.3    76.9   82.6
    AlexNet       RW        68.9     76.0    69.0     66.3     50.0   68.6      67.9    50.0   60.6
                  Diff       2.9      8.0    15.9      -0.9    33.9   13.8     -10.6    26.9   22.0       111.9 (12.4)
                  NW        70.0     91.9    84.1     69.9     89.4   86.9      66.4    87.9   85.5
   ResNet18       RW        68.9     85.8    81.4     68.5     73.3   81.0      68.9    80.9   80.0
                  Diff       1.1      6.1     2.7       1.4    16.1    5.9      -2.5     7.0    5.5        37.8 (4.2)


could enable the deployment of new capabilities across         TrustZone. However, in both works, the secure world
the ML pipeline. Securely assigning specialized hard-          (TrustZone) is trusted, making them vulnerable to mali-
ware—such as GPUs and NPUs—to realm could sig-                 cious actors within the secure world. This is a significant
nificantly accelerate inference computation. More impor-       concern, as [8] demonstrated, current implementations of
tantly, device assignment opens the possibility of protect-    TrustZone suffer from critical vulnerabilities. To address
ing the entire inference pipeline within the TEE boundary.     these issues, REZONE [49] proposes a system that de-
Although our current system protects the model itself from     privileges the TEE’s operating system, offering enhanced
NW adversaries, it does not protect the source of input        protection against potentially malicious TEE components.
data. In safety-critical applications—such as health moni-     Li et al. [50] Introduces a method to allocate large mem-
toring or autonomous driving—corrupted inputs can pose         ory for TrustZone apps by modifying OP-TEE. However,
serious risks. Thus, achieving strong guarantees requires      the total amount of memory available to OP-TEE remains
securing the entire inference workflow, including:(1) input    limited to the configured size at boot time.
generation, (2) delivery of inputs to the model, (3) gen-      Systems based on CCA. As CCA is still under de-
eration of outputs, and (4) consumption of outputs by the      velopment, there is limited prior work in this space.
requester.                                                     Formal methods is introduced in [29], [30] to verify
Membership Attack on LLMs. The larger memory size              security and functional correctness of RMM. SHELTER
of the realm, as compared to other on-device TEE solu-         [24] provides user-space isolation in the normal world
tions, allowed us to run LLMs within a realm. However,         using CCA hardware primitives. ACAI [25] is a system
we did not show the privacy benefit of running the LLM         that allows CCA realms to securely access PCIe-based
within a realm. Future works could explore the trade-off       accelerators with strong isolation guarantees. DEVLORE
between performance and privacy when deploying LLMs            [22] is a system that allows realm VM to access legitimate
in realm compared to NW. Currently, several studies have       integrated devices (e.g., keyboard) with necessary memory
examined MIA in black-box settings [42], [43] while oth-       protection and interrupt isolation from an untrusted hyper-
ers [44] have questioned the assumptions of previous at-       visor. GuaranTEE [27] took initial steps in using CCA for
tacks, investigating whether MIAs are feasible under more      ML tasks. This framework provides attestable and private
realistic conditions for LLMs. White-box MIAs for LLMs         machine learning on the edge using CCA and evaluated
remain an emerging area, with no proposed white-box            it for running a small model within realm. In this work,
attacks demonstrating consistent superiority over black-       we adopt their system model and utilize tracing tools to
box approaches.                                                estimate the system’s overhead.
Limitation. For the evaluations in this paper, we have
emulated CCA using FVP, our results are only initial ap-
                                                               7. Conclusion
proximation not obtained from a real hardware. Accurate            In this paper, we presented an in-depth evaluation of
evaluation can be done in the future when a real device        Arm’s Confidential Computing Architecture (CCA) as a
supporting Arm CCA will be available.                          solution to protect on-device models. We measure both
                                                               the overhead and the privacy gains of running models of
6. Related Works                                               various sizes and functionalities within a realm VM. Our
                                                               results indicate that, CCA can be a viable solution for
Model partitioning on end-devices. To overcome limi-           model protection. While various challenges still remain
tation of current TEEs, several works have proposed to         before CCA’s widespread deployment, we provide the first
partition model in which more sensitive parts are running      indication of its suitability as a mechanism to provide
within a TEE – these include shielding deep layers [11],       model protection.
[12], shallow layers [45], intermediate layers [46], non-
linear layers [47] within a TEE. Zhang et al. [13] showed      Acknowledgments
that those partitioning solutions are vulnerable to privacy        We wish to acknowledge the thorough and useful
attacks when public information like datasets and pre-         feedback from anonymous reviewers and our shepherd.
trained models engages in attacks.                             The research in this paper was supported by the UKRI
TEE extensions. There are works aim to overcome the            Open Plus Fellowship (EP/W005271/1 Securing the Next
limitations of TEE by introducing system-level tech-           Billion Consumer Devices on the Edge) and an Ama-
niques. SANCTUARY [48] and LEAP [9], for instance,             zon Research Awared “Auditable Model Privacy using
create isolated user-space enclaves in NW on top of            TEEs”.
References                                                                    [20] T. L. Foundation, “Arm Confidential Compute Archi-
                                                                                   tecture open-source enablement,” Accessed Feb 2025.
                                                                                   [Online]. Available: https://confidentialcomputing.io/webinars/
[1]   C. Orlandi, A. Piva, and M. Barni, “Oblivious neural network                 arm-confidential-compute-architecture-open-source-enablement/
      computing via homomorphic encryption,” EURASIP Journal on
      Information Security, vol. 2007, pp. 1–11, 2007.                        [21] A. Limited, “Fast Models Fixed Virtual Platforms
                                                                                   (FVP) Reference Guide,” Accessed Feb 2025. [Online].
[2]   R. Gilad-Bachrach, N. Dowlin, K. Laine, K. Lauter, M. Naehrig,               Available: https://developer.arm.com/Tools%20and%20Software/
      and J. Wernsing, “Cryptonets: Applying neural networks to en-                Fixed%20Virtual%20Platforms
      crypted data with high throughput and accuracy,” in International
      conference on machine learning. PMLR, 2016, pp. 201–210.                [22] A. Bertschi, S. Sridhara, F. Groschupp, M. Kuhne, B. Schlüter,
                                                                                   C. Thorens, N. Dutly, S. Capkun, and S. Shinde, “Devlore: Extend-
[3]   T. van Elsloo, G. Patrini, and H. Ivey-Law, “SEALion: A frame-               ing Arm CCA to Integrated Devices A Journey Beyond Memory
      work for neural network inference on encrypted data,” arXiv                  to Interrupt Isolation,” arXiv preprint arXiv:2408.05835, 2024.
      preprint arXiv:1904.12840, 2019.
                                                                              [23] C. Wang, F. Zhang, Y. Deng, K. Leach, J. Cao, Z. Ning, S. Yan, and
[4]   P. Mohassel and Y. Zhang, “Secureml: A system for scalable                   Z. He, “CAGE: Complementing Arm CCA with GPU Extensions,”
      privacy-preserving machine learning,” in 2017 IEEE symposium                 in Network and Distributed System Security (NDSS) Symposium,
      on security and privacy (SP). IEEE, 2017, pp. 19–38.                         2024.
[5]   M. S. Riazi, C. Weinert, O. Tkachenko, E. M. Songhori, T. Schnei-       [24] Y. Zhang, Y. Hu, Z. Ning, F. Zhang, X. Luo, H. Huang, S. Yan,
      der, and F. Koushanfar, “Chameleon: A hybrid secure computation              and Z. He, “SHELTER: Extending Arm CCA with Isolation in
      framework for machine learning applications,” in Proceedings of              User Space,” in 32nd USENIX Security Symposium (USENIX Se-
      the 2018 on Asia conference on computer and communications                   curity’23), 2023.
      security, 2018, pp. 707–721.                                            [25] S. Sridhara, A. Bertschi, B. Schlüter, M. Kuhne, F. Aliberti, and
[6]   A. Limited, “Learn the architecture - TrustZone for AArch64,”                S. Shinde, “ACAI: Extending Arm Confidential Computing Archi-
      Accessed Feb 2025. [Online]. Available: https://developer.arm.               tecture Protection from CPUs to Accelerators,” in 33rd USENIX
      com/documentation/102418/latest/                                             Security Symposium (USENIX Security’24), 2024.
                                                                              [26] J. Chen, Q. Zhou, X. Yan, N. Jiang, X. Jia, and W. Zhang,
[7]   “Software guard extensions.” [Online]. Available: https://en.
                                                                                   “Cubevisor: A multi-realm architecture design for running vm
      wikipedia.org/wiki/Software Guard Extensions
                                                                                   with arm cca,” in 2024 Annual Computer Security Applications
[8]   D. Cerdeira, N. Santos, P. Fonseca, and S. Pinto, “Sok: Understand-          Conference (ACSAC). IEEE, 2024, pp. 1–13.
      ing the prevailing security vulnerabilities in trustzone-assisted tee   [27] S. Siby, S. Abdollahi, M. Maheri, M. Kogias, and H. Haddadi,
      systems,” in 2020 IEEE Symposium on Security and Privacy (SP).               “GuaranTEE: Towards Attestable and Private ML with CCA,”
      IEEE, 2020, pp. 1416–1432.                                                   in Proceedings of the 4th Workshop on Machine Learning and
[9]   L. Sun, S. Wang, H. Wu, Y. Gong, F. Xu, Y. Liu, H. Han, and                  Systems, 2024, pp. 1–9.
      S. Zhong, “LEAP: TrustZone Based Developer-Friendly TEE for             [28] Y. Liu, R. Wen, X. He, A. Salem, Z. Zhang, M. Backes,
      Intelligent Mobile Apps,” IEEE Transactions on Mobile Comput-                E. De Cristofaro, M. Fritz, and Y. Zhang, “ML-Doctor: Holistic risk
      ing, 2022.                                                                   assessment of inference attacks against machine learning models,”
[10] OP-TEE,     “Q:     What’s       the    maximum         size     for          in 31st USENIX Security Symposium (USENIX Security 22), 2022,
     heap    and   stack?     can    it   be     changed.”      [Online].          pp. 4525–4542.
     Available:     https://optee.readthedocs.io/en/latest/faq/faq.html#      [29] X. Li, X. Li, C. Dall, R. Gu, J. Nieh, Y. Sait, and G. Stockwell,
     q-whats-the-maximum-size-for-heap-and-stack-can-it-be-changed                 “Design and verification of the arm confidential compute architec-
[11] F. Mo, A. S. Shamsabadi, K. Katevas, S. Demetriou, I. Leontiadis,             ture,” in 16th USENIX Symposium on Operating Systems Design
     A. Cavallaro, and H. Haddadi, “Darknetz: towards model privacy at             and Implementation (OSDI 22), 2022, pp. 465–484.
     the edge using trusted execution environments,” in Proceedings of        [30] A. C. Fox, G. Stockwell, S. Xiong, H. Becker, D. P. Mulligan,
     the 18th International Conference on Mobile Systems, Applications,            G. Petri, and N. Chong, “A Verification Methodology for the Arm®
     and Services, 2020, pp. 161–174.                                              Confidential Computing Architecture: From a Secure Specification
                                                                                   to Safe Implementations,” Proceedings of the ACM on Program-
[12] F. Mo, H. Haddadi, K. Katevas, E. Marin, D. Perino, and
                                                                                   ming Languages, vol. 7, no. OOPSLA1, pp. 376–405, 2023.
     N. Kourtellis, “PPFL: privacy-preserving federated learning with
     trusted execution environments,” in Proceedings of the 19th an-          [31] Y. Yuan, Z. Liu, S. Deng, Y. Chen, S. Wang, Y. Zhang, and
     nual international conference on mobile systems, applications, and            Z. Su, “Ciphersteal: Stealing input data from tee-shielded neural
     services, 2021, pp. 94–108.                                                   networks with ciphertext side channels,” in 2025 IEEE Symposium
                                                                                   on Security and Privacy (SP). IEEE Computer Society, 2024, pp.
[13] Z. Zhang, C. Gong, Y. Cai, Y. Yuan, B. Liu, D. Li, Y. Guo,                    79–79.
     and X. Chen, “No Privacy Left Outside: On the (In-) Security of
     TEE-Shielded DNN Partition for On-Device ML,” in 2024 IEEE               [32] ——, “Hypertheft: Thieving model weights from tee-shielded neu-
     Symposium on Security and Privacy (SP). IEEE Computer Society,                ral networks via ciphertext side channels,” in Proceedings of the
     2024, pp. 52–52.                                                              2024 on ACM SIGSAC Conference on Computer and Communica-
                                                                                   tions Security, 2024, pp. 4346–4360.
[14] A. Limited, “Arm Confidential Compute Architecture,” Accessed
     Feb 2025. [Online]. Available: https://www.arm.com/architecture/         [33] A. Limited, “Fast Models Reference Guide,” Accessed Feb
     security-features/arm-confidential-compute-architecture                       2025. [Online]. Available: https://developer.arm.com/Tools%
                                                                                   20and%20Software/Fixed%20Virtual%20Platforms
[15] M. Sardar, T. Fossati, and S. Frost, “SoK: Attestation in confiden-
                                                                              [34] “Shrinkwrap,” Accessed Feb 2025. [Online]. Available: https:
     tial computing,” ResearchGate pre-print, 2023.
                                                                                   //shrinkwrap.docs.arm.com/en/latest/overview.html
[16] TrustedFirmware, “TF-RMM,” Accessed Feb 2025. [Online].                  [35] “TensorFlow Lite Label Image,” Accessed Feb 2025.
     Available: https://www.trustedfirmware.org/projects/tf-rmm                    [Online]. Available: https://github.com/tensorflow/tensorflow/tree/
[17] A. Limited, “Learn the architecture - AArch64 Exception Model,”               master/tensorflow/lite/examples/label image
     Accessed Feb 2025. [Online]. Available: https://developer.arm.           [36] “TensorFlow Label Image,” Accessed Feb 2025. [On-
     com/documentation/102412/latest/                                              line]. Available: https://github.com/tensorflow/tensorflow/tree/
[18] Linaro, “qemu,” Accessed Feb 2025. [Online]. Available:                       master/tensorflow/examples/label image
     https://git.codelinaro.org/linaro/dcap/qemu                              [37] “GPT2,” Accessed Feb 2025. [Online]. Available: https://
                                                                                   huggingface.co/openai-community/gpt2
[19] A. Bennée, “Building an RME stack for QEMU.”
     [Online]. Available: https://linaro.atlassian.net/wiki/spaces/QEMU/      [38] ggerganov, “llama.cpp,” Accessed Feb 2025. [Online]. Available:
     pages/29051027459/Building+an+RME+stack+for+QEMU                              https://github.com/ggerganov/llama.cpp
[39] “GPT2-large,” Accessed Feb 2025. [Online]. Available: https:         VMs, but for each one, we need to use a compatible
     //huggingface.co/openai-community/gpt2-large                         branch of linux-cca (which has a similar name to the
[40] “TinyLlama/TinyLlama-1.1B-Chat-v0.5,” Accessed Feb 2025. [On-        branch of that VMM).
     line]. Available: https://huggingface.co/TinyLlama/TinyLlama-1.
     1B-Chat-v0.5                                                         FVP Accuracy. FVP promises to accurately model the
                                                                          instruction behavior of a real processor [21], [33]. How-
[41] “Mad24-410 arm confidential compute architecture open-source
     enablement update,” May 17, 2024. [Online]. Available: https:        ever, some micro architectural behaviors (e.g., caching
     //resources.linaro.org/en/resource/rEjhEezEvnNMC3LALzUTrr            and memory accesses) are different between FVP and an
[42] F. Galli, L. Melis, and T. Cucinotta, “Noisy Neighbors: Effi-        actual device, making cyclic and timing measurements
     cient membership inference attacks against LLMs,” arXiv preprint     unreliable. [33]. Therefore, we do not report timing or
     arXiv:2406.16565, 2024.                                              cycle-accurate performance results from the simulation.
[43] R. Xie, J. Wang, R. Huang, M. Zhang, R. Ge, J. Pei, N. Z. Gong,      While some studies [23]–[25] have prototyped CCA on
     and B. Dhingra, “ReCaLL: Membership Inference via Relative           existing Armv8-A hardware, these platforms lack essential
     Conditional Log-Likelihoods,” arXiv preprint arXiv:2406.15968,       features—such as GPC support in system registers and
     2024.
                                                                          accurate cache behavior—which pose challenges to the
[44] M. Duan, A. Suri, N. Mireshghallah, S. Min, W. Shi, L. Zettle-       accuracy of such prototypes. Although our framework
     moyer, Y. Tsvetkov, Y. Choi, D. Evans, and H. Hajishirzi, “Do
     membership inference attacks work on large language models?”         is evaluated using FVP, these hardware-based prototypes
     arXiv preprint arXiv:2402.07841, 2024.                               may still be valuable for others, particularly for enabling
[45] J. Hou, H. Liu, Y. Liu, Y. Wang, P.-J. Wan, and X.-Y. Li,            cycle-level and timing evaluations.
     “Model Protection: Real-time privacy-preserving inference service    Instruction tracing in FVP. FVP can be used in con-
     for model privacy at the edge,” IEEE Transactions on Dependable
     and Secure Computing, vol. 19, no. 6, pp. 4270–4284, 2021.
                                                                          junction with tracing tools and plugins to provide detailed
                                                                          information about the behavior of CCA. Particularly, we
[46] T. Shen, J. Qi, J. Jiang, X. Wang, S. Wen, X. Chen, S. Zhao,
     S. Wang, L. Chen, X. Luo et al., “SOTER: Guarding Black-box
                                                                          use GenericTrace to choose a trace source (e.g., instruc-
     Inference for General Neural Networks at the Edge,” in 2022          tions in our case) and ToggleMTIPlugin to enable/disable
     USENIX Annual Technical Conference (USENIX ATC 22), 2022,            tracing during runtime. We configure GenericTrace to
     pp. 723–738.                                                         trace and print each instruction executed by an FVP’s
[47] Z. Sun, R. Sun, C. Liu, A. R. Chowdhury, L. Lu, and S. Jha, “Shad-   processor core, along with other metadata. The metadata
     ownet: A secure and efficient on-device model inference system       includes the security state and the exception level of the
     for convolutional neural networks,” in 2023 IEEE Symposium on
     Security and Privacy (SP). IEEE, 2023, pp. 1596–1612.
                                                                          core when running that instruction, and the total number
                                                                          of instructions executed until that point in time. Using
[48] F. Brasser, D. Gens, P. Jauernig, A.-R. Sadeghi, and E. Stapf,
     “SANCTUARY: ARMing TrustZone with User-space Enclaves.”
                                                                          ToggleMTIPlugin, FVP can be set to be sensitive to a
     in NDSS, 2019.                                                       particular assembly instruction7 . Whenever this instruction
[49] D. Cerdeira, J. Martins, N. Santos, and S. Pinto, “ReZone: Dis-      is executed by the FVP’s processor core, tracing is auto-
     arming TrustZone with TEE Privilege Reduction,” in 31st USENIX       matically started/stopped. We add this instruction at points
     Security Symposium (USENIX Security 22), 2022, pp. 2261–2279.        in the code to enable and disable GenericTrace. This is
[50] J. Li, X. Luo, H. Lei, and J. Cheng, “Teem: Supporting large         necessary to reduce the size of the trace file and only get
     memory for trusted applications in arm trustzone,” IEEE Access,      what it is necessary for each experiment. Lastly, similar to
     2024.                                                                what has already been done by Sridhara et al. [25], we add
[51] TrustedFirmware, “TF-A,” Accessed Feb 2025. [Online].                a set of assembly instructions to the code to mark specific
     Available: https://www.trustedfirmware.org/projects/tf-a             points (e.g., beginning and end of inference) in the final
[52] A. Limited, “linux-cca,” Accessed Feb 2025. [Online]. Available:     trace file. Later, by analyzing this trace file, we can get
     https://gitlab.arm.com/linux-arm/linux-cca                           the result of evaluations including number of instructions
[53] Buildroot, “buildroot,” Accessed Feb 2025. [Online]. Available:      executed (for example between the beginning and end of
     https://github.com/buildroot/buildroot                               inference).
[54] “kvmtool-cca,” Accessed Feb 2025. [Online]. Available: https:
     //gitlab.arm.com/linux-arm/kvmtool-cca
                                                                          Runtime isolation. Since FVP simulates a multi-core
                                                                          device, additional measures are necessary to ensure that
                                                                          the target workload is executed exclusively on the traced
Appendix A.                                                               core. To achieve this, we utilize a kernel-command line
Experimental Setup                                                        parameter called isolcpus to isolate one core from the
                                                                          hypervisor’s general load balancing and scheduling algo-
Software stack. We use the Trusted Firmware-A [51]                        rithms. This ensures that the hypervisor’s scheduler does
(v2.11), and the Trusted Firmware implementation of                       not assign any processes to the traced core by default.
RMM [16] (tf-rmm-v0.5.0) as the Monitor and the RMM                       Subsequently, during runtime, we use the taskset tool to
of the software stack (Figure 1), respectively. We sep-                   explicitly direct the hypervisor to use only the isolated
arately build linux-cca [52] and the file system for each                 core for the process that oversees the virtual machine.
experiment and pass them to Shrinkwrap. Shrinkwrap later                  On-demand memory delegation. During the VM’s boot
boots FVP with the necessary firmware and the given ker-                  process, the hypervisor [52] delegates only the physical
nel and file system. We also use Buildroot [53], to create                pages necessary to load the kernel and file system im-
customized file systems for each experimental setup. In                   ages. The remaining memory in the VM’s address space
order to create a virtual machine, we need to provision                   is delegated on-demand, triggered by the first access to
a virtual machine manager (VMM) to the hypervisor’s                       those addresses. To decouple this one-time overhead from
file system. Both kvmtool-cca [54] (cca/rmm-v1.0-eac5)
and Linaro’s QEMU [18] (cca/v3) have support for realm                      7. We used HLT 0x1337
the main experiment in each evaluation, we address it         booting and termination escalates with the size of the VM,
by running a user-space program within the VM. This           as reflected in the experimental settings detailed in Table
program temporarily allocates all available memory in         2, with the exception of boot overhead between 4 and
the virtual machine’s user space and fills it with binary      5 . This results suggests that, although realm booting
1’s. This ensures that the hypervisor delegates the entire    and termination represent one-time costs, they become
memory beforehand, preventing any memory delegation           significantly burdensome when deploying larger models,
during the main experiment.                                   which typically necessitate larger VM sizes.
Experimental Hosts. The membership inference attack
in Section 4.3 is conducted on a system with dual Intel
Xeon Gold 6136 CPUs (48 cores, 3.7 GHz max) and 251
GiB RAM, utilizing an NVIDIA Quadro GV100 GPU
for acceleration. The environment run on Ubuntu 22.04.1
with kernel 6.5.0. Although FVP results are independent
of the host platform, we report the system specifications
for completeness. We conduct all FVP-related experiments
on a Lenovo ThinkCentre M75t Gen 2 with 16GB RAM
and an 8-core AMD Ryzen 7 PRO 3700 processor (OS:
Ubuntu 22.04.4 LTS). We set FVP to have two clusters,
each with four cores supporting Armv9.2-A and 4GB of
RAM.

Appendix B.
Inference Overhead
    In order to identify the source of overhead within the
inference computation, we conduct an additional experi-
ment to quantify the engagement of firmware and software
components during inference computation. Using config-
uration 2 , we deploy two VMs – one within the Realm
world and the other in the NW – with both performing
the same task (a single inference). We then measured
the number of instructions executed by each software
and firmware component in the system. The results are
presented in Table 5. In both experiments, the number
of executed instructions at EL0 and EL1 are relatively the
same. However, significant differences emerge at EL2 and
EL3, which are the main contributors to the overhead in
the realm. Specifically, the virtualization support for the
NW VM requires only 14.8 million instructions executed
by the hypervisor. In contrast, the Realm VM required
16.84 million instructions executed by the hypervisor, with
an additional 41.18 million instructions executed by the
RMM and 5.13 million by the Monitor. These results
suggest that the RMM is the main source of overhead,
accounting for more than twice the number of executed
instructions by the hypervisor. Worth noting that these
measurements are done during the inference computation
and there is no I/O involved.

Appendix C.
Realm Setup Overhead
    In this section, we evaluate the overhead associated
with booting and terminating a realm VM in comparison
to a baseline scenario (a NW VM). As illustrated in Table
6, the overhead for booting and terminating a realm VM
is substantial, with observed increases ranging from 867%
to 21,902% for booting and from 644% to 3,521% for
termination. These elevated overheads are primarily due
to the additional RMM checks and processes required
for page delegation (during boot) and reclaming those
pages (during termination). Notably, the overhead for both
TABLE 5: Number of instructions (in millions) executed by each software/firmware component for a single inference
in both normal and realm VMs. These results correspond to experimental setting 2 in Table 2.
                          Exception       Realm VM Experiment               NW VM Experiment
                            Level      Realm World    Normal World      Realm World   Normal World
                            EL0           240.14          0.04               0           240.18
                            EL1            24.68            0                0            23.85
                            EL2            41.18         16.84               0            14.80
                            EL3                    5.13                             0




TABLE 6: Mean (standard deviation) of number of instructions executed for realm boot and termination. Each
experimental setting is described in Table 2.
                                                  VM Boot (106 )                       VM Termination (106 )
            Experimental Setting
                                      Realm VM         NW VM        Overhead   Realm VM      NW VM       Overhead
                     2               7630.1 (52.6)    788.7 (0.7)     867%      619.9 (3.3)  83.3 (0.1)      644%
                     4             24960.7 (132.9) 1246.6 (0.9)      1902%     2332.4 (2.4)  93.1 (0.2)     2405%
                     5              44499.3 (10.9)   2329.4 (5.2)    1832%     5156.4 (6.9) 142.4 (0.3)     3521%
                     6              21101.5 (71.4)   1195.0 (0.2)    1665%     1325.3 (2.4)  87.1 (0.1)     1421%
