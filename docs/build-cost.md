# Build cost

The harness records under `runs/dsh/`, summed by `scripts/build_cost.py`.
This file is generated: run `make build-cost` after a session lands and commit
the result. One row per session id. A session that failed and was retried has
a sibling named `*.failed-*.json`, and the sibling is dropped so one session is
counted once.

| session | effort | exit | wall s | input | output | cache reads | total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `w22` | high | 0 | 7,052 | 187,702 | 136,376 | 43,198,848 | 43,522,926 |
| `w17-matrix` | max | 0 | 5,116 | 211,922 | 191,409 | 51,325,440 | 51,728,771 |
| `w13` | max | 0 | 4,768 | 200,831 | 132,398 | 27,010,944 | 27,344,173 |
| `w26` | high | 0 | 3,028 | 222,418 | 167,302 | 74,043,008 | 74,432,728 |
| `w15` | high | 0 | 2,663 | 322,039 | 224,421 | 109,819,008 | 110,365,468 |
| `w16` | max | 0 | 2,613 | 210,566 | 198,855 | 69,386,240 | 69,795,661 |
| `w25` | high | 0 | 2,565 | 176,653 | 108,778 | 27,048,448 | 27,333,879 |
| `w14` | max | 0 | 1,689 | 226,436 | 216,268 | 75,252,480 | 75,695,184 |
| `w24` | high | 0 | 1,387 | 242,538 | 130,021 | 50,805,120 | 51,177,679 |
| `w27` | high | 0 | 1,175 | 174,221 | 99,831 | 29,823,104 | 30,097,156 |
| `w23c` | max | 0 | 633 | 56,565 | 68,491 | 5,775,104 | 5,900,160 |
| `w17-close` | high | 0 | 384 | 99,620 | 48,785 | 6,104,320 | 6,252,725 |
| `w23b` | low | 0 | 362 | 65,904 | 57,248 | 6,131,456 | 6,254,608 |
| `w0-sdk-check` | low | 0 | 8 | 9,461 | 80 | 9,216 | 18,757 |
| `w17` | max | 1 | 3 | 0 | 0 | 0 | 0 |
| `w23-verify-1789669979` | off | 0 | 2 | 11,184 | 4 | 0 | 11,188 |
| `w23-final-1789670399` | off | 0 | 2 | 4,016 | 4 | 7,168 | 11,188 |
| `w23-toolfix` | low | 1 | 2 | 0 | 0 | 0 | 0 |
| `w23-verify-1789669953` | off | 1 | 0 | 0 | 0 | 0 | 0 |
| **19 sessions** | | | **33,452** | **2,422,076** | **1,780,271** | **575,739,904** | **579,942,251** |

Totals: **579,942,251 tokens** (2,422,076 input, 1,780,271 output, 575,739,904 cache reads) over **9.3 hours** of recorded wall time.

W1 through W12 ran through the web interface and wrote no record under
`runs/dsh/`, so this is a floor rather than the full cost of the build.

Dropped as a retry of a session already in the table: `w23-final-1789670399.failed-20260917-184006-608592.json`.
