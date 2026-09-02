# Investigation Report: `ADDRESS_RANGE` END convention in the public v1.1 Ghidra XML

## 1. Methodology

* Parsed the public v1.1 XML (`<FUNCTION>` + `<ADDRESS_RANGE>`, `<SYMBOL>`, `<CODE_BLOCK>`), the public v1.1 linker map (`0001:` namespace), and the public v1.1 `.bytes` image.
* **Namespace check (done first, it invalidates a prior assumption):** the XML, map, and `.bytes` file are in *one* namespace — the map's `0001:` segment values — with file offset = value − 0x10000 (verified for `IsSamplePlaying_` 0x96180→file 0x86180, `LbSqrL_` 0x96260→0x86260). The `sub_86xxx` auto-names are map values too (their bytes at file 0x76250 decode as clean code; at file 0x86250 they're mid-instruction). So any appearance of "mixed conventions" in this data is not real.
* For every function: linear x86-32 decode from `START` with capstone, walking to `END` (never stopping at `ret` — multi-return functions have several), trimming trailing all-pad instructions (`00`/`90`/`CC`), recording where the **last real instruction ends** (`lastCodeEnd`), whether any instruction straddles `END` (`MID`), the byte at `END`, and the next known function/symbol start.
* Classification: `INCL` if lastCodeEnd == END; `EXCL_PAD` if == END−1 with a pad byte at END; `GAP_BEFORE_E`/`MID`/etc. otherwise.
* Independent cross-validation with GNU `objdump` on a 10-function stratified slice (all named functions + one per anomaly class).
* Same classifier run on the beta2 XML/bytes (offset convention for beta2: file offset = map value, verified at 0x93A50) as a second build's cross-check.

## 2. Sample size

| CorpusFunctionsWith ADDRESS_RANGEMulti-range |       |                          |    |
| -------------------------------------------- | ----- | ------------------------ | -- |
| **v1.1 XML**                                 | 3,271 | 3,271 (0 missing, 0 OOB) | 41 |
| beta2 XML                                    | 3,822 | —                        | 31 |

Byte-level classification applied to **all** 3,271 v1.1 functions (no sub-sampling); beta2 ran as a control.

## 3. Results

**v1.1 (the corpus in question):**

| ClassCountShare                                              |           |           |
| ------------------------------------------------------------ | --------- | --------- |
| **INCL — last real instruction ends exactly at END**         | **3,265** | **99.8%** |
| GAP_BEFORE_E (decode desync / data tail / tail-`jmp` thunks) | 3         | 0.09%     |
| EXCL_PAD (single trailing pad/nop at END)                    | 2         | 0.06%     |
| END_MID_INSTRUCTION                                          | 1         | 0.03%     |

Breakdown of INCL by name class: bullfrog_lib 91, crt/sys 199, miles_ail 38, other 321, ghidra-auto 2,615 — uniform, not confined to one library. Size buckets: <64B 1,453; 64–256B 1,063; 256–1k 598; >1k 151 — uniform.

**Independent objdump agreement: 10/10** — including all four named targets and representatives of every anomaly class (details in §6).

**Named verifications (all INCL, ****`ret`****/terminal at END):**

| FunctionRangeSizeLast insn |                    |         |                                              |
| -------------------------- | ------------------ | ------- | -------------------------------------------- |
| `IsSamplePlaying_`         | [0x96180, 0x9625E] | **223** | ret @ 0x9625E                                |
| `LbSqrL_`                  | [0x96260, 0x962A1] | **66**  | ret @ 0x962A1                                |
| `LbScreenSetup_`           | [0x962F0, 0x962FF] | 16      | ret                                          |
| `UnpackM1_`                | [0xB9CFC, 0xB9E98] | 413     | ret                                          |
| `_AIL_sample_status`       | [0xB23F0, 0xB24FC] | 269     | ret                                          |
| `sub_10060` (multi-ret)    | [0x10060, 0x1008C] | 45      | ret @ 0x1008C (also rets at 0x1007C/0x10086) |

`IsSamplePlaying_` and `LbSqrL_` end at END, one byte apart from the next function (pad `00` at END+1; `LbSqrL_` prologue at END+2) — exactly the structure found in beta2 and v1.0 (byte-verified last turn).

**Call census (Q6), capstone over all 2,527 cleanly-decodable v1.1 functions:**

| ObservableValue                                                          |                                 |
| ------------------------------------------------------------------------ | ------------------------------- |
| Functions with ≥1 call (any)                                             | 1,850 = **73.2%**               |
| Functions with ≥1 **direct external** call                               | 1,772 = **70.1%**               |
| …of which call to a **known mapped/XML symbol**                          | 1,771 (70.1%) — effectively all |
| Functions with ≥1 indirect call                                          | 321 = 12.7%                     |
| Direct call sites: target known / unknown / internal                     | 9,555 / 1 / 5                   |
| Functions with internal conditional branches (contrast: not relocations) | 2,188 = 86.6%                   |

So direct external calls are the **norm** (70% of functions; 99.94% of direct call sites resolve to known symbols), internal branches are ubiquitous, and only **one** call site in the whole corpus targets an unknown address.

## 4. Counterexamples (actively sought, found small)

* **Where ****`END−START`**** is correct:** 2 functions (`sub_6BBF0` [0x6BBF0,0x6BC0F], `sub_768B0` [0x768B0,0x768BF]) end at END−1 with a trailing pad/nop at END — only here does `END−START` equal code length (and `END−START+1` overcounts by the pad). 0.06%.
* **Ranges that include padding:** same 2 functions (single byte). No case found with multi-byte padding inside a v1.1 range.
* **Functions whose last instruction doesn't end at END:** 3 GAP cases + 1 MID case, all Ghidra-auto `sub_*` names: `sub_C25EA` (950 B; contains a switch/jump-table → linear decode desync — a decoding limitation, not obviously a range error), `sub_D3810` (129 B; ends `jmp` — tail-jump thunk), `sub_E19C0` (2,859 B; likely table-bearing), `sub_D36D1` (45 B; MID). 0.1%.
* **The 41 multi-range functions** (e.g., `sub_86270` with two ranges [0x86270,0x8628A] + [0x8625E,0x86260]) — primary-range-only consumers mis-size these too; 1.25%.
* **The beta2 control is the big counterexample to "the XML generally does this":** beta2's export is *not* cleanly inclusive — 59.8% MID (ranges over-extended), e.g. `Ethereal::Resync(void)` [0x10059,0x100B4]: real end (last `ret`) at 0x10092, **34 trailing bytes** inside the range. The beta2 export is raw/uncurated; the v1.1 export is curated and coherent. **Do not carry v1.1 conventions to beta2 or vice versa.**

## 5. Verdict

**Systematic, not isolated.** The curated v1.1 Ghidra XML uses **inclusive END** — the last byte of the last real instruction — with 99.8% uniformity across libraries, sizes, and name classes, independently confirmed by objdump 10/10.

Consequently, **any** consumer that computes size as `END − START` (exclusive arithmetic) will register essentially every function one byte short. The observed `IsSamplePlaying_` registered 222 vs true 223 is not a one-off: it is the signature of that arithmetic applied to a uniformly inclusive corpus, and it equally predicts `LbSqrL_` = 65 vs true 66, `_AIL_sample_status` = 268 vs true 269, `UnpackM1_` = 412 vs 413, etc. If the corpus's registered sizes were derived from the XML with `END−START`, the −1 error affects ~99.8% of registrations (≈3,265 functions) — the one-byte size errors are as widespread as the corpus. (What remains unknown, and unobservable publicly, is whether the private registration pipeline actually derived sizes that way; the single data point reported for `IsSamplePlaying_` is fully consistent with it.)

The external-call observation is different in kind: 70.1% of ordinary mapped functions have direct external calls, essentially all to *known, nameable* targets — so "zero external calls" as a hard gate excludes the majority of ordinary functions, and the class that *does* pass it (call-free leaves like `LbSqrL_`) is the narrow showcase class, not the population. Internal branches (86.6%) are the non-relocation control flow that should **not** be treated like calls. No claim about private G1–G6 policy is made; these are observable facts about the canon.

## 6. Confidence and limitations

* **High confidence in the convention finding:** uniform 99.8% result, 10/10 independent objdump agreement on a stratified slice including all named functions and each anomaly class, and structural corroboration (pad → next function prologue) at multiple boundaries.
* **Limitation:** "last instruction" is determined by *linear* decode from the entry; functions with embedded tables (`sub_C25EA`) desync and were set aside (3–4 cases). Ghidra's actual CFG-based boundaries could differ in rare cases, so the tail of the distribution (0.1%) shouldn't be over-read.
* **Limitation:** beta2's control shows the convention is *export-specific*; the beta2 numbers therefore neither confirm nor deny v1.1 — only limit generalization.
* **Not assessed (private/absent):** the corpus registration code, G3's implementation, and any promotion pipeline. The 41 multi-range functions are worth a follow-up if the corpus assumes one range per function.

## 7. Exact files and addresses used

* `genewars-re-helpers/symbols/gw-genewars-1_1-nov_1996.xml` (3,421,357 B; 3,271 functions; 3,316 ranges; 2,565 CODE_BLOCKs; 2,014 SYMBOLs)
* `genewars-re-helpers/symbols/gw-genewars-1_1-nov_1996.map` (72,398 B; 926 `0001:` symbols; `IsSamplePlaying_` line 199, `LbSqrL_` line 200, `_AIL_sample_status` line 427)
* `genewars-re-helpers/symbols/gw-genewars-1_1-nov_1996.bytes` (999,424 B; file = map value − 0x10000)
* `genewars-re-helpers/symbols/gw-genewars-beta2-jul_1996.xml` / `.bytes` (control; beta2 file offset = map value)
* Tested addresses: 0x96180, 0x96260, 0x962F0, 0x10060, 0xB9CFC, 0xB23F0, 0x6BBF0, 0x768B0, 0xD36D1, 0xD3810, 0xC25EA (v1.1); 0x10059 (beta2).

No code changed; no private implementation assumed correct or faulted.
