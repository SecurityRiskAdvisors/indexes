# Threat Simulation Indexes

Each Threat Simulation Index is a curated list of test cases derived from the threat groups of interest for members of a given industry.  Security Risk Advisors (SRA) collaborates  with experts in threat intelligence and cyber defense at targeted organizations to identify techniques which should be prioritized for defense testing.  Each Index evolves over time as the threat landscape changes for an industry.

One of the goals of each Threat Simulation Index is to allow organizations to compare objective defense scores against peers.  Visit the  [Defense Success Metric blog post on SRA.io](https://sra.io/blog/the-road-to-benchmarked-mitre-attck-alignment-defense-success-metrics/)  for more detail.

## Methodology
Test cases are based on MITRE-tracked intelligence and the general process for determining test cases for inclusion is as follows:

1. Identify initial list of groups with principal members
2. Map groups to MITRE-tracked groups and filter out non-MITRE groups
3. Review intelligence report for each group
    1. Remove anything produced before 2020
    2. Remove reports that do not provide enough information for simulation purposes
    3. Cut groups lacking intelligence
4. Extract TTP information from intelligence reports then develop full test cases for each
    1. Exclude TTPs that likely do not act as worthwhile simulation candidates
5. Filter out items from list to balance plan composition

## Use
Threat Simulation Indexes may be used independently or with SRA's [VECTR](https://vectr.io) application.
