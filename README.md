#### Snort Preprocessor to parse ModSecurity Core RuleSet
A Proof-of-Concept project started to turn ModSecurity into sniffer mode and with Snort Inline capability to drop packet once the packet matches with the attack signatures. Therefore, the payload should not be able to get to the target and reaching to the 5th layer and above. (Isn't it?)

#### TODO:
1. Looking for collaboration
    - To port the ModSecurity Engine into the preprocessor
    - Build a CRS parser
    - Trigger Snort Inline capability

2. Documentation (?)
3. Any suggestions (?)

#### License

GPLv License. Copyright (c) 2015 Fakhri Zulkifli. See [License](https://github.com/d0lph1n98/Snort-ModSec-CRS-Parser/blob/master/LICENSE).
