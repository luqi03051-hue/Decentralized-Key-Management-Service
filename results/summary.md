| Configuration | runs | PKG requests (total) | PKG busy (s) | PKG requests during user phase | user phase wall (s) | p50 (ms) | p95 (ms) | users with valid keys | reqs / trusted user | busy / trusted user (s) | PKG reachable |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Baseline (PKG issues all keys) | 3 | 100 ± 0 | 17.25 ± 0.12 | 100 ± 0 | 17.34 ± 0.12 | 1718 ± 30 | 1830 ± 88 | 300/300 | - | - | yes |
| Case A (PKG enrolls m trusted users only) | 3 | 5 ± 0 | 1.06 ± 0.08 | 0 ± 0 | 4.13 ± 0.02 | 412 ± 4 | 606 ± 13 | 285/285 | 57.0 ± 0.0 | 3.30 ± 0.05 | yes |
| Case B (PKG stopped after enrollment) | 3 | 5 ± 0 | 0.99 ± 0.01 | 0 ± 0 | 4.17 ± 0.08 | 421 ± 11 | 601 ± 33 | 285/285 | 57.0 ± 0.0 | 3.31 ± 0.05 | no |
