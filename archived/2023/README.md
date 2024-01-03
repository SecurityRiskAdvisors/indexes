# Threat Simulation Indexes

Each Threat Simulation Index is a curated list of test cases derived from the threat groups of interest for members of a given industry using MITRE-tracked intelligence. Security Risk Advisors (SRA) collaborates with experts in threat intelligence and cyber defense at targeted organizations to identify priorities for defense testing.  

One of the goals of each Threat Simulation Index is to allow organizations to compare objective defense scores against peers. Visit the [Defense Success Metric blog post on SRA.io](https://sra.io/blog/the-road-to-benchmarked-mitre-attck-alignment-defense-success-metrics/) for more information.

### Release Cycle

Indexes are released once per year. Throughout the year, an Index may receive minor quality of life changes but will not deviate significantly from the initial release. New yearly releases start fresh and are not designed to be compatible with previous releases. Overlap between Indexes in the same industry for different years is incidental, as is overlap across industries.

## 2023 Indexes

The following Indexes are available for 2023:

- [Financial Services](fs-index-2023/)
- [Retail & Hospitality](rh-index-2023/)
- [Health](h-index-2023/)

### Composition

Expand the below section to view Index group compositions

<details>
  <summary>Expand</summary>

**Financial Services**

- [APT28](https://attack.mitre.org/groups/G0007/)
- [APT29](https://attack.mitre.org/groups/G0016/)
- [APT41](https://attack.mitre.org/groups/G0096/)
- [Bazar](https://attack.mitre.org/software/S0534/)
- [Bumblebee](https://attack.mitre.org/software/S1039/) (& Quantum)
- [LAPSUS$](https://attack.mitre.org/groups/G1004/)
- [QakBot](https://attack.mitre.org/software/S0650/)

**Retail & Hospitality**

- [APT41](https://attack.mitre.org/groups/G0096/)
- [Conti](https://attack.mitre.org/software/S0575/)
- [Bumblebee](https://attack.mitre.org/software/S1039/) (& Quantum)
- [FIN7](https://attack.mitre.org/groups/G0046/)
- [LAPSUS$](https://attack.mitre.org/groups/G1004/)
- [QakBot](https://attack.mitre.org/software/S0650/)

**Health**

- [APT41](https://attack.mitre.org/groups/G0096/)
- [Bazar](https://attack.mitre.org/software/S0534/)
- [BlackTech](https://attack.mitre.org/groups/G0098/)
- [Bumblebee](https://attack.mitre.org/software/S1039/) (& Quantum)
- [Conti](https://attack.mitre.org/software/S0575/)
- [Kimsuky](https://attack.mitre.org/groups/G0094/)
- [QakBot](https://attack.mitre.org/software/S0650/)

</details>

## Intent & Use

Indexes are designed to be used by human operators as part of simulated attack scenarios such as purple teams. Operators should have general familiarity with attacker techniques, payload generation, and infrastructure management.

Individual Index requirements can be found in that Index's folder in the REQUIREMENTS.md file.

Indexes can be imported directly into [VECTR](https://vectr.io) using the merged YAML document for that Index.

### Additional Notes

- Operators are free to use their payload generation procedures of choice as long as the resulting payload(s) complies with the general description provided by the test case and its associated documentation.
- Where possible, Operators should avoid using default settings for their tools. This includes, but is not limited to: shellcode, C2 traffic signatures, and default artifacts
- Some test cases can be performed through alternative execution methods. However, Operators should exercise caution in methods that produce significantly different detection artifacts for the core behaviors. For example, executing a .NET payload via an `execute-assembly` style harness is generally acceptable whereas substituting one credential dumping method for another should be avoided.

## Development Process

Test cases are based on MITRE-tracked intelligence and the general process for determining test cases for inclusion is as follows:

1. Identify initial list of groups with principal members
2. Map groups to MITRE-tracked groups and filter out non-MITRE groups
3. Review intelligence report for each group
    1. Remove anything produced before the look-back period of two years
    2. Remove reports that do not provide enough information for simulation purposes
    3. Cut groups lacking intelligence
4. Extract TTP information from intelligence reports then develop full test cases for each
    1. Exclude TTPs that likely do not act as worthwhile simulation candidates
5. Filter out items from list to balance plan composition

