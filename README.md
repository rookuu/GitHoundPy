# GitHound.py

---

A python implementation of the Githound collector for BloodHound OpenGraph. I will work to keep it up to date with the main powershell version. 

Credit and tons of props to the Specterops team for the main implementation, for a detailed breakdown on the features check the main repo:

[https://github.com/SpecterOps/GitHound/tree/main](https://github.com/SpecterOps/GitHound/tree/main)

# Usage

```
usage: GitHoundV3.py [-h] --organization ORGANIZATION [--output OUTPUT] [--verbose] [--include-security]

GitHub BloodHound Ingestor

options:
  -h, --help            show this help message and exit
  --organization ORGANIZATION, -o ORGANIZATION
                        GitHub organization name
  --output OUTPUT, -f OUTPUT
                        Output file path (default: githound_<org>.json)
  --verbose, -v         Enable verbose logging
  --include-security, -s
                        Include security findings (default: True)
```