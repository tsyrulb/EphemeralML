                                               Confidential Computing on NVIDIA Hopper GPUs: A
                                                           Performance Benchmark Study
                                                   Jianwei Zhu, Hang Yin, Peng Deng† , Aline Almeida‡ , Shunfan Zhou
                                                                Phala Network, † Fudan University, ‡ io.net
                                                        {jianweiz, hangyin, shelvenzhou}@phala.network,
                                                              †
                                                                pdeng21@m.fudan.edu.cn, ‡ aline@io.net
arXiv:2409.03992v4 [cs.DC] 5 Nov 2024




                                                                                   November 6, 2024


                                                                                         Abstract
                                                  This report evaluates the performance impact of enabling Trusted Execution Environments
                                              (TEE) on NVIDIA Hopper GPUs for large language model (LLM) inference tasks. We benchmark
                                              the overhead introduced by TEE mode across various LLMs and token lengths, with a particular
                                              focus on the bottleneck caused by CPU-GPU data transfers via PCIe. Our results indicate that
                                              while there is minimal computational overhead within the GPU, the overall performance penalty
                                              is primarily attributable to data transfer. For the majority of typical LLM queries, the overhead
                                              remains below 7%, with larger models and longer sequences experiencing nearly zero overhead.


                                        Acknowledgments
                                        We would like to express our gratitude to the io.net [io.] and IOG Foundation [Fou] for their generous
                                        grant, which made this research possible. We also extend our thanks to Engage Stack [Sta], the cloud
                                        service provider, for providing the necessary hardware and technical support.


                                        1     Introduction
                                        Trusted Execution Environments (TEEs) are increasingly important in machine learning and AI due
                                        to growing security requirements in both enterprise and decentralized applications [SAB15, MSM+ 18,
                                        AKKH18]. The introduction of TEE-enabled GPUs, such as the NVIDIA H100 and H200, adds an
                                        extra layer of protection for sensitive data but may impact performance. Understanding these trade-
                                        offs, particularly for large-scale machine learning tasks, is crucial for adopting TEE in high-performance
                                        AI applications [YMY+ 22, WO24].
                                            This report quantifies the performance overhead of enabling TEE on the NVIDIA Hopper archi-
                                        tecture GPUs during LLM inference tasks, identifying where the overhead arises and under what
                                        conditions it can be minimized.


                                        2     Background
                                        2.1    Trusted Execution Environment
                                        A TEE is a hardware-based security feature that isolates computations, preventing unauthorized ac-
                                        cess and tampering, even from the operating system or the physical hardware owner. As the core
                                        technology enabling Confidential Computing, TEEs create secure enclaves where sensitive data and
                                        code are processed with encryption, ensuring confidentiality and integrity even if the broader system is
                                        compromised [SAB15]. Traditionally implemented in CPUs, TEE technology was extended to GPUs
                                        by NVIDIA in 2023, enabling tamper-proof and confidentiality-preserving computation inside the GPU
                                        with minimal performance penalty [DGK+ 23].



                                                                                             1
2.2    NVIDIA Hopper Architecture
The NVIDIA Hopper architecture marks a significant milestone as the first GPU family to support
TEE [nVI]. In TEE mode, the GPU operates in an isolated and secure environment where data
transfers between the CPU and GPU are encrypted. This is achieved through “bounce buffers”, which
protect all inputs and outputs during transit between the CPU’s encrypted memory and the GPU’s
internal memory [DGK+ 23].
    To maintain end-to-end security, the GPU works in conjunction with CPU TEEs, such as Intel’s
TDX [Int] or AMD’s SEV-SNP [AMD, SS20], securing communication channels between the GPU
driver and interacting software. This setup prevents unauthorized access and ensures data integrity
throughout the process.
    The Hopper series also implement remote attestation to verify the GPU’s identity and the authen-
ticity of its firmware. Additionally, Secure Boot ensures that only authenticated firmware is executed
during the GPU’s boot process, further strengthening security.

2.3    Performance Impact
Enabling TEE on the NVIDIA Hopper GPU introduces performance overheads primarily due to ad-
ditional encryption and decryption during secure data transfer [MYF+ 24]. While the GPU’s internal
computation remains unaffected, the main bottleneck lies in the CPU-GPU I/O, particularly when
data is exchanged via PCIe. This impact varies with the size of the data transfer. The following
sections present experimental results quantifying these effects across various use cases.
    With the TEE-enabled NVIDIA Hopper GPU, it becomes crucial to quantify performance trade-
offs during practical use cases. In the next section, we outline the methodology used to assess the
performance impact of TEE during LLM inference tasks.


3     Methodology
To evaluate the performance overhead, we conducted experiments comparing inference throughput
and latency with TEE mode enabled and disabled, under different models, input and output lengths,
and batch size setups. Our primary focus was to reveal the performance penalty in real-world large
language model (LLM) inference tasks.

3.1    Metrics
The primary metrics were evaluated following typical evaluation frameworks [AAK+ 24]:

    • TTFT (Time To First Token): The time from request arrival to the generation of the first
      output token. It includes scheduling delay and prompt processing. Lower TTFT is essential for
      real-time applications, while higher TTFT is tolerable in batch processing.
    • ITL (Inter-Token Latency): The time between generating each token during decoding. This
      directly affects the perceived model speed. A rate of around 6 tokens per second is necessary for
      a smooth user experience, assuming an average reading speed.
    • TPS (Tokens per Second): The average rate of token generation during decoding. It is
      calculated as the number of tokens generated divided by the total decoding time.

    • Latency: The total execution time per request, including scheduling, prompt processing, and
      token generation. Lower normalized latency improves system throughput, especially under high
      query loads.
    • QPS (Queries per Second): The maximum load a system can handle while meeting latency
      targets. Higher QPS reduces serving costs and is a key measure of system capacity.




                                                   2
3.2      Test Scenarios
Experiments were structured to explore the impact of TEE mode under diverse conditions:
     • TEE mode ON vs. TEE mode OFF: Tests were performed with TEE mode alternately
       enabled and disabled on the H-series GPUs, allowing for a direct comparison of performance.

     • Sequence Lengths: Various token lengths were tested by sampling the ShareGPT Dataset
       [ano] to simulate different LLM inference tasks.
     • Batch Size: Both fixed batch sizes (1, 4, and 16) and dynamic batch sizes determined by
       vLLM [KLZ+ 23] were tested to simulate the performance for serving real-time requests and
       batch requests.

3.3      Experimental Setup
3.3.1     Infrastructure
The experiments were set up with the following hardwares, respectively.

    Component          Specification                        Setup 1               Setup 2
                       Model                        NVIDIA H100 NVL          NVIDIA H200 NVL
    GPU                Memory                            94 GB                    141 GB
                       Bandwidth                        3.9 TB/s                 4.8 TB/s
                       Model                         AMD EPYC 9V84       INTEL XEON PLATINUM 8558
    CPU                Cores                              96                        48
                       TEE Technology                  SEV-SNP                     TDX
    Memory             Total Memory                         314 GB                128 GB
                       CUDA Version                           12.5                  12.5
    Software           Driver Version                       555.42.06             555.42.06
                       Kernel Driver Version                550.90.07             550.90.07

                                               Table 1: Hardware Setup


3.3.2     Application
The experiments utilized the benchmark suite of vLLM v0.5.4 (rev:            4db5176) [KLZ+ 23].

3.3.3     Models
Three LLMs were used for inference:

     • Meta-Llama-3.1-8B-Instruct
     • Phi-3-14B-128k-Instruct
     • Meta-Llama-3.1-70B-Instruct with 4-bit bitsandbytes quantization to fit into a single Hopper
       GPU


4       Results
Conclusion 1: The average overhead is less than 9%. We quantified the overhead by mea-
suring the throughput with TEE mode enabled versus disabled, across varying input sizes and model
configurations, as shown in Table 2.
    1 The overhead is negative due to the precision loss.
    2 The overhead is negative due to the precision loss.




                                                             3
 GPU       Model                        TPS (tokens/s)                             QPS (req/s)
                                  TEE-on TEE-off Overhead                TEE-on     TEE-off Overhead
           LLama-3.1-8B            123.2985      132.3618       6.85%    18.2141    18.8208    3.22%
 H100      Phi3-14B-128k            66.5845       69.7787       4.58%     7.1760     7.3456    2.31%
           Llama-3.1-70B            2.4822        2.4789       -0.13%1    0.8325     0.8295   -0.36%2
           LLama-3.1-8B            121.0412      132.7830      8.84%     29.5973    32.0134   7.55%
 H200      Phi3-14B-128k            68.4287       72.9825      6.24%     12.8294    13.8558   7.41%
           Llama-3.1-70B            4.0797        4.1753       2.29%      2.1874     2.2011   0.63%

Table 2: Performance comparison of TEE-on and TEE-off modes for various models in terms of TPS
(tokens per second) and QPS (queries per second).


    The throughput is measured in two ways: the average throughput of the outputted tokens per
second (TPS), and that of the parallel requests the hardware can handle (QPS). TPS is measured by
running the model with a batch size of 1. It shows the pure latency overhead introduced by the TEE
mode and reflects the performance of real-time requests. QPS is measured by maximizing the query
throughput with a dynamically optimized batch size. It reflects the minimal average overhead the
TEE mode brings.
    We observed a difference in the impact of TEE mode between H100 and H200 in Table 2. First,
compared to H100, TEE mode introduces more overhead in H200 when runing the same model. Second,
the impact of TEE mode on QPS is more noticeable in H200. In H100, the impact of TEE mode on
TPS is nearly double that of QPS, but in H200, the difference decreased significantly.
Conclusion 2: The overhead reduces as the model size grows. As shown in Table 2, the
smallest model (Llama-3.1-8B) has the highest overhead. The medium-sized model (Phi-3-14B-
128k) has roughly two-thirds of the overhead compared to the smaller one. Notably, the largest model
(Llama-3.1-70B) has a negligible overhead close to zero in H100.
Conclusion 3: The latency is the main factor contributing to the overhead of the TEE
mode. Table 3 shows the overhead introduced to the latency measured by TTFT and ITL. TTFT
has a higher overhead compared with ITL, indicating the bottleneck is likely introduced by the I/O
instead of the computation happening inside the TEE. Nevertheless, the overhead becomes trivial when
hosting heavy computation models like Llama-3.1-70B. Additionally, TEE mode has also a greater
impact on TTFL and ITL in H200 compared to H100.

 GPU       Model                                 TTFT (s)                            ITL (s)
                                  TEE-on         TEE-off Overhead        TEE-on     TEE-off Overhead
           LLama-3.1-8B             0.0288        0.0242       19.03%     1.6743     1.5549    7.67%
 H100      Phi3-14B-128k            0.0546        0.0463       18.02%     3.7676     3.5784    5.29%
           Llama-3.1-70B            0.5108        0.5129       -0.41%3   94.8714    95.2395   -0.39%4
           LLama-3.1-8B             0.0364        0.0301       20.95%     1.7158     1.5552   10.33%
 H200      Phi3-14B-128k            0.0524        0.0417       25.60%     3.6975     3.4599    6.87%
           Llama-3.1-70B            0.4362        0.4204        3.75%    57.3855    55.9771   2.52%

Table 3: Comparison of TTFT (Time to First Token) and ITL (Inter Output Token Latency) for
TEE-on and TEE-off modes across models.

Conclusion 4: The overhead reduces as the token size grows. As shown in Figure 1, the
throughput overhead reduces when the sequence length grows, measured by the total input and output
token count. The detailed throughput metrics across various sequence lengths can be found in Table
4.
  3 The overhead is negative due to the precision loss.
  4 The overhead is negative due to the precision loss.
  5 The overhead is negative due to the precision loss.
  6 The overhead is negative due to the precision loss.




                                                           4
                                                                                                    Short   Medium      Long

                                                                            9.00%

                                                                            8.00%

                                                                            7.00%

                                                                            6.00%

                                                                            5.00%




                                                           TPS (tokens/s)
                                                                            4.00%

                                                                            3.00%

                                                                            2.00%

                                                                            1.00%

                                                                            0.00%

                                                                            -1.00%
                                                                                          LLama-3.1-8B       Phi3-14B-128k         Llama-3.1-70B



                       (a) H100                                                                          (b) H200

Figure 1: Throughput overhead across different token sizes (length of the input and output sequence).
Short sequences are no longer than 100 tokens. Medium sequences are no longer than 500 tokens.
Long sequences are between 501 and 1500 tokens.

GPU    Model             TPS - short (tokens/s)       TPS - medium (tokens/s)                                  TPS - long (tokens/s)
                       TEE-on TEE-off Overhead       TEE-on TEE-off Overhead                                TEE-on TEE-off Overhead
       LLama-3.1-8B    127.0310   136.8282   7.16%   122.9356                  132.0464         6.90%       122.9705           131.7333        6.65%
H100   Phi3-14B-128k   70.9799    74.7556    5.05%    66.1690                   69.3104         4.53%        66.2987            69.4176        4.49%
       Llama-3.1-70B    2.5983     2.6073    0.34%    2.4413                    2.4374         -0.16%5       2.5245             2.5168        -0.30%6
       LLama-3.1-8B    124.1744   136.2283   8.85%   120.4250                  132.2366         8.93%       121.3849           132.9002            8.66%
H200   Phi3-14B-128k   71.8940    76.2754    5.74%    67.8290                   72.3372         6.23%        68.5863            73.2384            6.35%
       Llama-3.1-70B    4.2261     4.3295    2.39%    4.0425                    4.1386          2.32%        4.0947             4.1886             2.24%


Table 4: Performance comparison of TEE-on and TEE-off modes across different sequence lengths in
terms of TPS (tokens per second). Short sequences are no longer than 100 tokens. Medium sequences
are no longer than 500 tokens. Long sequences are between 501 and 1500 tokens.


Conclusion 5: TEE can reach typical throughput. Here, we use NVIDIA H100 for the case study.
Our experiments revealed that, with medium-sized inputs, the H100 GPU achieves 130 TPS for Llama-
3.1-8B, while the larger Phi-3-14B model reaches approximately 6 TPS. These results demonstrate the
robust performance of the H100 GPU across models of varying complexity.
    More detailed experimental data for H100 is shown in Figures 2, 3, and 4, and for H200 in Figures
5, 6, and 7.




               Figure 2: Throughput vs output token size for LLama-3.1-8B in H100.




               Figure 3: Throughput vs output token size for Phi3-14B-128k in H100.




                                                       5
              Figure 4: Throughput vs output token size for Llama-3.1-70B in H100.




              Figure 5: Throughput vs output token size for LLama-3.1-8B in H200.




              Figure 6: Throughput vs output token size for Phi3-14B-128k in H200.




              Figure 7: Throughput vs output token size for Llama-3.1-70B in H200.


5    Conclusion
Our results show that as input size grows, the efficiency of TEE mode increases significantly. When
computation time within the GPU dominates overall processing time, the I/O overhead introduced by
TEE mode diminishes, allowing efficiency to approach nearly 99%.
   Efficiency growth is more pronounced in larger models, such as Phi3-14B-128k and Llama-
3.1-70B, due to their greater computational demands, which result in longer GPU processing times.
Consequently, the I/O overhead becomes increasingly trivial as model size increases.
   The total token size (sum of input and output token size) significantly influences the throughput
overhead. Larger total token counts lead to higher efficiencies, as they enhance the ratio of computation
time to I/O time.
   These findings underscore the scalability of TEE mode in handling large-scale LLM inference tasks,
particularly as input sizes and model complexities grow. The minimal overhead in high-computation
scenarios validates its applicability in secure, high-performance AI workloads.


References
[AAK+ 24] Amey Agrawal, Anmol Agarwal, Nitin Kedia, Jayashree Mohan, Souvik Kundu, Nipun
          Kwatra, Ramachandran Ramjee, and Alexey Tumanov. Metron: Holistic performance
          evaluation framework for llm inference systems. arXiv preprint arXiv:2407.07000, 2024.
[AKKH18] Gbadebo Ayoade, Vishal Karande, Latifur Khan, and Kevin Hamlen. Decentralized iot
         data management using blockchain and trusted execution environment. In 2018 IEEE


                                                   6
           international conference on information reuse and integration (IRI), pages 15–22. IEEE,
           2018.
[AMD]      AMD. Amd secure encrypted virtualization-secure nested paging. https://www.amd.com/
           en/developer/sev.html. Accessed: 2024-09-12.
[ano]      anon8231489123. Sharegpt vicuna unfiltered. https://huggingface.co/datasets/
           anon8231489123/ShareGPT_Vicuna_unfiltered. Accessed: 2024-09-04.
[DGK+ 23] Gobikrishna Dhanuskodi, Sudeshna Guha, Vidhya Krishnan, Aruna Manjunatha, Michael
          O’Connor, Rob Nertney, and Phil Rogers. Creating the first confidential gpus: The team at
          nvidia brings confidentiality and integrity to user code and data for accelerated computing.
          Queue, 21(4):68–93, 2023.

[Fou]      IOG Foundation. Iog foundation: The decentralization of cloud computing. https://iog.
           net/. Accessed: 2024-10-24.
[Int]      Intel. Intel trust domain extensions. https://www.intel.com/content/www/us/en/
           developer/tools/trust-domain-extensions/overview.html. Accessed: 2024-09-12.

[io.]      io.net. io.net. https://io.net/. Accessed: 2024-10-24.
[KLZ+ 23] Woosuk Kwon, Zhuohan Li, Siyuan Zhuang, Ying Sheng, Lianmin Zheng, Cody Hao Yu,
          Joseph E. Gonzalez, Hao Zhang, and Ion Stoica. Efficient memory management for large
          language model serving with pagedattention. In Proceedings of the ACM SIGOPS 29th
          Symposium on Operating Systems Principles, 2023.

[MSM+ 18] Sinisa Matetic, Moritz Schneider, Andrew Miller, Ari Juels, and Srdjan Capkun.
          {DelegaTEE}: Brokered delegation using trusted execution environments. In 27th USENIX
          Security Symposium (USENIX Security 18), pages 1387–1403, 2018.
[MYF+ 24] Apoorve Mohan, Mengmei Ye, Hubertus Franke, Mudhakar Srivatsa, Zhuoran Liu, and
          Nelson Mimura Gonzalez. Securing ai inference in the cloud: Is cpu-gpu confidential
          computing ready? In 2024 IEEE 17th International Conference on Cloud Computing
          (CLOUD), pages 164–175. IEEE, 2024.
[nVI]      nVIDIA. Nvidia confidential computing. https://www.nvidia.com/en-us/data-center/
           solutions/confidential-computing/. Accessed: 2024-10-24.

[SAB15]    Mohamed Sabt, Mohammed Achemlal, and Abdelmadjid Bouabdallah. Trusted execution
           environment: What it is, and what it is not. In 2015 IEEE Trustcom/BigDataSE/Ispa,
           volume 1, pages 57–64. IEEE, 2015.
[SS20]     AMD Sev-Snp. Strengthening vm isolation with integrity protection and more. White
           Paper, January, 53:1450–1465, 2020.

[Sta]      Engage Stack. Engage stack – the enterprise gpu cloud. https://engagestack.io/.
           Accessed: 2024-10-24.
[WO24]     Qifan Wang and David Oswald. Confidential computing on heterogeneous systems: Survey
           and implications. arXiv preprint arXiv:2408.11601, 2024.

[YMY+ 22] Ardhi Wiratama Baskara Yudha, Jake Meyer, Shougang Yuan, Huiyang Zhou, and Yan
          Solihin. Lite: a low-cost practical inter-operable gpu tee. In Proceedings of the 36th ACM
          International Conference on Supercomputing, pages 1–13, 2022.




                                                  7
