# Generate ssh keys in a loop and check their uniqueness

This is a safeguard against a repeat of
[DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1).

Good writeup by Matt Palmer:
[How I Tripped Over the Debian Weak Keys Vulnerability](https://www.hezmatt.org/~mpalmer/blog/2024/04/09/how-i-tripped-over-the-debian-weak-keys-vuln.html)

Author uses only ed25519; other key algorithms are not tested.

## License and copyright

Copyright 2024 Vitaly Potyarkin

```
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
```
