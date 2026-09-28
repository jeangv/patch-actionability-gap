# Characterization Hand Check (frozen corpus, after C4)

Calls for the sample in `docs/v5_nvd_characterization_sample.md` (seed
20260927, drawn by `src/freeze_manifest.py` from the frozen corpus after the
C4 vendor scope denylist). Kept separate because re-running the manifest
rewrites the sample file. Summary numbers are in
`data/freeze/characterization_summary.json`; the first draw, which found the
C4 problem, is in `docs/characterization_first_draw_pre_c4.md`.

**AI assistance.** An AI model (Claude) made the first in-scope call on each
record from its CVE List V5 description and vendor, and the author reviewed
every call. Scope categories are the same as in the first-draw document.

## Result

| Sample | In scope | Borderline | Out of scope |
|---|---:|---:|---:|
| V5-only (30) | 23 | 3 | 4 |
| NVD-only (30) | 9 | 10 | 11 |
| NVD-only, second draw after the first C4 pass (seed 20260928) | 13 | 9 | 8 |

Across the two post-C4 NVD-only draws: 22 in scope, 19 borderline, 19 out of
60. Decision (2026-09-28): lock the corpus with this rate stated, and add a
description-based scope screen to the Week 8 results script so every result
is reported on the full corpus and on the screened subset.

## V5-only calls

| # | CVE | Call | Why |
|---:|---|---|---|
| 1 | CVE-2026-9533 | in | Totolink CA750-PoE access point |
| 2 | CVE-2025-34053 | in | AVTECH IP cameras, DVR, NVR |
| 3 | CVE-2026-19924 | in | Tenda AC10 router |
| 4 | CVE-2025-6565 | in | Netgear WNCE3001 wireless bridge |
| 5 | CVE-2024-14007 | in | TVT NVMS-9000 DVR/NVR/IP camera firmware |
| 6 | CVE-2021-40031 | out | Huawei smartphone camera module |
| 7 | CVE-2021-47816 | in | Thecus N4800Eco NAS |
| 8 | CVE-2026-20766 | in | Milesight cameras |
| 9 | CVE-2026-14169 | out | ads-tec Industrial IT, industrial |
| 10 | CVE-2026-10188 | in | Tenda W12 access point |
| 11 | CVE-2026-71950 | in | D-Link DWR-M961 cellular router |
| 12 | CVE-2023-5826 | borderline | Netentsec NS-ASG application security gateway |
| 13 | CVE-2025-6559 | in | Sapido wireless routers |
| 14 | CVE-2021-37109 | out | Huawei phone modem |
| 15 | CVE-2024-6108 | in | Genexis Tilgin home gateway |
| 16 | CVE-2026-86149 | in | Tenda CP3 camera |
| 17 | CVE-2026-71933 | in | DrayTek VigorSwitch, SMB switch |
| 18 | CVE-2026-19788 | in | Tenda AC1206 router |
| 19 | CVE-2025-5408 | in | WAVLINK routers and extenders |
| 20 | CVE-2025-34226 | out | OpenPLC Runtime, industrial control software |
| 21 | CVE-2014-125122 | in | Linksys WRT120N router |
| 22 | CVE-2024-2648 | borderline | Netentsec NS-ASG application security gateway |
| 23 | CVE-2026-10162 | in | TRENDnet TEW-432BRP router |
| 24 | CVE-2026-9294 | in | Edimax BR-6428NS router |
| 25 | CVE-2026-48132 | borderline | Check Point Security Gateway, enterprise firewall |
| 26 | CVE-2026-82592 | in | D-Link DIR-825M router |
| 27 | CVE-2026-9462 | in | Edimax EW-7438RPn range extender |
| 28 | CVE-2026-7137 | in | Totolink A8000RU router |
| 29 | CVE-2026-6630 | in | Tenda F451 router |
| 30 | CVE-2024-8655 | in | Mercury MNVR816 network video recorder |

## NVD-only calls

| # | CVE | Call | Why |
|---:|---|---|---|
| 1 | CVE-2003-1416 | out | BisonFTP Server, software |
| 2 | CVE-2025-35021 | borderline | Abilis CPX, VoIP gateway |
| 3 | CVE-2018-17021 | in | ASUS GT-AC5300 router |
| 4 | CVE-2025-57636 | in | D-Link C1 device web server |
| 5 | CVE-2015-0929 | in | SerVision HVG video gateway |
| 6 | CVE-2021-37167 | out | Swisslog Healthcare HMI3 panel, medical |
| 7 | CVE-2019-7383 | in | Systrome Cumilon ISG SMB security gateways |
| 8 | CVE-2023-47614 | borderline | Telit Cinterion cellular IoT modules |
| 9 | CVE-2017-20024 | borderline | Solar-Log energy data logger |
| 10 | CVE-2023-46373 | in | TP-Link TL-WDR7660 router |
| 11 | CVE-2017-5947 | out | OnePlus phones |
| 12 | CVE-2013-4630 | borderline | Huawei AR branch routers |
| 13 | CVE-2008-4383 | out | Alcatel OmniSwitch, enterprise switch |
| 14 | CVE-2023-35697 | out | SICK ICR890-4, industrial scanner |
| 15 | CVE-2008-7161 | borderline | Fortinet FortiGate-1000, enterprise firewall |
| 16 | CVE-2018-10544 | in | Meross MSS110 smart plug |
| 17 | CVE-2021-21891 | borderline | Lantronix PremierWave 2050, industrial wireless module |
| 18 | CVE-2022-25437 | in | Tenda AC9 router |
| 19 | CVE-2007-3368 | borderline | Polycom SoundPoint IP 601 SIP phone |
| 20 | CVE-2019-16274 | borderline | DTEN D5/D7 conferencing displays |
| 21 | CVE-2025-1709 | out | Endress+Hauser, industrial |
| 22 | CVE-2018-14993 | out | Asus ZenFone, Android phone |
| 23 | CVE-2018-11720 | borderline | Xovis people-counting sensors |
| 24 | CVE-2018-11316 | in | Sonos wireless speakers |
| 25 | CVE-2017-17307 | out | Huawei smartphones |
| 26 | CVE-2020-12739 | out | Fanuc CNC, industrial |
| 27 | CVE-2008-0708 | out | HP USB floppy drive for ProLiant servers |
| 28 | CVE-2011-2779 | out | HP ArcSight connector, software |
| 29 | CVE-2018-5923 | borderline | HP enterprise printers |
| 30 | CVE-2025-63674 | in | Blurams security camera |

Why the rest gets through: the mobile-handset soft exclusion matches the
product string, not the description, so "Huawei Smartphones" and "Android
device" descriptions pass; the industrial and medical term lists have no
entry for terms like CNC. The Week 8 description screen is where that gets
addressed.
