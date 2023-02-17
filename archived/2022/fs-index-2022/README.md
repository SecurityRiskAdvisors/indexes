# Threat Simulation Index - Financial Services - 2022

Financial Services Threat Simulation Index 2022 Release v1

## Groups/Software Groups

- [Zirconium](https://attack.mitre.org/groups/G0128/)
- [Gamaredon](https://attack.mitre.org/groups/G0047/)
- [Lazarus](https://attack.mitre.org/groups/G0032/)
- [Winnti](https://attack.mitre.org/groups/G0044/)
- [Kimsuky](https://attack.mitre.org/groups/G0094/)
- [APT41](https://attack.mitre.org/groups/G0096/)
- [APT29](https://attack.mitre.org/groups/G0016/)
- [APT28](https://attack.mitre.org/groups/G0007/)
- [Wizard Spider](https://attack.mitre.org/groups/G0102/)
- [Trickbot](https://attack.mitre.org/software/S0266/)

## Files

- fsi2022_merged.yml : all test cases in a single file
- navigator.json : MITRE Navigator layer for technique IDs
- summary.csv : test case names, MITRE technique IDs, campaigns, and descriptions for all test cases in CSV format
- techniques/ : directory of all test cases broken down by campaign

## Methodology

1. Identify initial list of groups with principal members
2. Map groups to MITRE-tracked groups and filter out non-MITRE groups
3. Review intelligence report for each group 
   1. Remove anything produced before 2020
   2. Remove reports that do not provide enough information for simulation purposes
   3. Cut groups lacking intelligence
4. Extract TTP information from intelligence reports then develop full test cases for each
   1. Exclude TTPs that likely do not act as worthwhile simulation candidates
5. Filter out items from list to balance plan composition

