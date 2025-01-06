# Threat Simulation Indexes

 The Threat Simulation Index is a curated list of test cases derived from the threat groups and techniques of interest for members of the Index working group. Security Risk Advisors (SRA) collaborates with experts in threat intelligence and cyber defense at targeted organizations to identify priorities for defense testing.  

One of the goals of each Threat Simulation Index is to allow organizations to compare objective defense scores against peers. Visit the [Defense Success Metric blog post on SRA.io](https://sra.io/blog/the-road-to-benchmarked-mitre-attck-alignment-defense-success-metrics/) for more information.

### Release Cycle

Indexes are released once per year. Throughout the year, an Index may receive minor quality of life changes but will not deviate significantly from the initial release. New yearly releases start fresh and are not designed to be compatible with previous releases. Overlap between Indexes in the same industry for different years is incidental, as is overlap across industries. 

Starting with the 2025 Index, test plans are no longer created per Industry but rather as a singular, unified Index. 

### Composition

The 2025 Index is based on both timely threat intelligence as well as expert curated content.
The included threat/software groups are listed below.

<details>
  <summary>Expand</summary>

- APT29
- Sandworm
- APT41
- VoltTyphoon
- APT45
- PeachSandstorm
- Cicada3301
- KeyGroup
- ScatteredSpider
- TA577
- 404Keylogger
- AgentTesla
- Akira
- AsyncRAT
- BlackBasta
- ClearFake
- Latrodectus
- Medusa
- NetSupport
- Play
- Qilin
- RansomHub
- SocGholish
- XWorm

</details>

## Intent & Use

Indexes are designed to be used by human operators as part of simulated attack scenarios such as purple teams. Operators should have general familiarity with attacker techniques, payload generation, and infrastructure management.

Individual Index requirements can be found in that Index's folder in the REQUIREMENTS.md file as well as the operator notebook.

Indexes can be imported directly into [VECTR](https://vectr.io) using the merged YAML document for that Index. This document and other artifacts are generated using [Market Maker](https://github.com/SecurityRiskAdvisors/marketmaker). 

The 2025 Index includes test cases for the infrastructure-as-a-service platforms AWS and Azure. 
While you are free to test both platforms, community scores will only include one of the two platforms.

### Additional Notes

- Operators are free to use their payload generation procedures of choice as long as the resulting payload(s) complies with the general description provided by the test case and its associated documentation.
- Where possible, operators should avoid using default settings for their tools. This includes, but is not limited to: shellcode, C2 traffic signatures, and default artifacts
- Some test cases can be performed through alternative execution methods. However, operators should exercise caution in methods that produce significantly different detection artifacts for the core behaviors. For example, executing a .NET payload via an `execute-assembly` style harness is generally acceptable whereas substituting one credential dumping method for another should be avoided.
