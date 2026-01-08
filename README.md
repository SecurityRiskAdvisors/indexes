# Threat Simulation Indexes

The Threat Simulation Index is a curated list of test cases derived from the threat groups and techniques of interest for members of the Index working group (120 organizations across Finance, Health, Pharma, Tech, Energy, Manufacturing, and Retail). Security Risk Advisors (SRA) collaborates with experts in threat intelligence and cyber defense at targeted organizations to identify priorities for defense testing.

One of the goals of each Threat Simulation Index is to allow organizations to compare objective defense scores against peers. Visit the [Threat Resilience Metric (TRM) blog post on SRA.io](https://sra.io/blog/the-road-to-benchmarked-mitre-attck-alignment-defense-success-metrics/) for more information.

### Release Cycle

Indexes are released once per year. Throughout the year, an Index may receive minor quality of life changes but will not deviate significantly from the initial release. New yearly releases start fresh and are not designed to be compatible with previous releases. Overlap between Indexes in the same industry for different years is incidental, as is overlap across industries.

Starting with the 2025 Index, test plans are no longer created per Industry but rather as a singular, unified Index. After years of building threat index test plans, we identified that the highest priority threat groups and techniques remain very similar across industries. This gives us the ability to provide a test plan that prepares all organizations, regardless of industry or size, to build resilience against the latest threats. It also gives us the ability to both have a larger overall dataset as well as support even more granular benchmarks in the future (for example, Insurance within Finance or Providers within Healthcare, and also general organization size).

### Composition

The 2026 Index is based on both timely threat intelligence as well as expert curated content.
The included threat/software groups are listed below.

<details>
  <summary>Expand</summary>

- APT29
- Lumma 
- Akira
- ShinyHunters 
- Storm-2603 
- MuddyWater 
- Cephalus 
- Qilin 
- Play 
- Famous Chollima 
- Vidar 
- XWorm 
- RansomHub 
- SocGholish 
- Gootloader 
- UNC1549 
- Scattered Spider

</details>

## Intent & Use

Indexes are designed to be used by human operators as part of simulated attack scenarios such as purple teams. Operators should have general familiarity with attacker techniques, payload generation, and infrastructure management.

Individual Index requirements can be found in that Index's folder in the REQUIREMENTS.md file as well as the operator notebook.

Indexes can be imported directly into [VECTR](https://vectr.io) using the merged YAML document for that Index. This document and other artifacts are generated using [Market Maker](https://github.com/SecurityRiskAdvisors/marketmaker). 

### Additional Notes

- Operators are free to use their payload generation procedures of choice as long as the resulting payload(s) complies with the general description provided by the test case and its associated documentation.
- Where possible, operators should avoid using default settings for their tools. This includes, but is not limited to: shellcode, C2 traffic signatures, and default artifacts
- Some test cases can be performed through alternative execution methods. However, operators should exercise caution in methods that produce significantly different detection artifacts for the core behaviors. For example, executing a .NET payload via an `execute-assembly` style harness is generally acceptable whereas substituting one credential dumping method for another should be avoided.
