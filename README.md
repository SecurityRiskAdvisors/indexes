# Threat Simulation Indexes

Each Threat Simulation Index is a curated list of Test Cases derived from the actions of threat actors who have been observed targeting an industry.  Security Risk Advisors (SRA) collaborates  with experts in threat intelligence and cyber defense at targeted organizations to identify techniques which should be prioritized for defense testing.  Each Index evolves over time as the threat landscape changes for an industry.

One of the goals of each Threat Simulation Index is to allow organizations to compare objective defense scores against peers.  Visit the  [Defense Success Metric blog post on SRA.io](https://sra.io/blog/the-road-to-benchmarked-mitre-attck-alignment-defense-success-metrics/)  for more detail.

## Methodology
Test cases are based on MITRE-tracked intelligence and the general process for determining test cases for inclusion is as follows:

1. Identify initial list of groups of interest
2. Map groups to MITRE-tracked groups and filter out non-MITRE groups
3. Extract intelligence for technique examples for each group and filter out anything older than 12 months 
    - this information is available in MITRE Enterprise CTI data
4. For each technique example, read source intelligence to determine if activity can be simulated
5. Develop list for simulatable activities
6. Filter out items from list that do not provide worthwhile simulation candidates
7. Develop full test cases for remaining items

## Use
Threat Simulation Indexes may be used independently or with SRA's [VECTR](https://vectr.io) application.
