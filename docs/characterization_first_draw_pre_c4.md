# Characterization, First Draw (before the C4 vendor scope fix)

Hand check of the first sample drawn by `src/freeze_manifest.py` (seed
20260927) from the corpus as frozen on 2026-09-28, before the vendor scope
denylist was applied to the NVD path. This draw is what found the C4
problem, so it is kept as evidence. The current sample and its check are in
`docs/v5_nvd_characterization_sample.md`.

**AI assistance.** An AI model (Claude) made the first in-scope call on each
record from its CVE List V5 description and vendor, and the author reviewed
the calls. Scope is the study's: consumer and small-business network
equipment, gateways, access points, IP cameras, NAS, and similar consumer IoT.
Out of scope: industrial control, medical, automotive, mobile handsets,
general-purpose computers and servers, enterprise datacenter and carrier
networking, and pure software. Borderline covers embedded devices the scope
statement does not name (SIP phones, printers, industrial wireless modules,
enterprise access points and firewalls sold to SMBs).

## Result

| Sample | In scope | Borderline | Out of scope |
|---|---:|---:|---:|
| V5-only (30) | 22 | 2 | 6 |
| NVD-only (30) | 9 | 6 | 15 |

## V5-only calls

| # | CVE | Call | Why |
|---:|---|---|---|
| 1 | CVE-2026-9440 | in | Edimax BR-6478AC router |
| 2 | CVE-2025-2520 | out | Honeywell Experion PKS, industrial control |
| 3 | CVE-2026-19748 | in | Tenda CH/CP/TC series IP cameras |
| 4 | CVE-2025-58282 | out | Huawei camera module, phone OS component |
| 5 | CVE-2024-0143 | out | NVIDIA nvJPEG2000, software library |
| 6 | CVE-2021-35402 | in | PROLiNK PRC2402M router |
| 7 | CVE-2021-47770 | out | OpenPLC, industrial control software |
| 8 | CVE-2026-19811 | in | TOTOLINK A800R router |
| 9 | CVE-2026-11557 | in | Tenda F451 router |
| 10 | CVE-2026-10121 | in | TRENDnet TEW-432BRP router |
| 11 | CVE-2026-71921 | in | DrayTek VigorSwitch, SMB switch |
| 12 | CVE-2023-5681 | borderline | Netentsec NS-ASG application security gateway |
| 13 | CVE-2025-5408 | in | WAVLINK routers and extenders |
| 14 | CVE-2020-6790 | out | Bosch Video Streaming Gateway Windows installer |
| 15 | CVE-2024-54126 | in | TP-Link Archer C50 router |
| 16 | CVE-2026-82592 | in | D-Link DIR-825M router |
| 17 | CVE-2026-71904 | in | DrayTek VigorAP access points |
| 18 | CVE-2026-18284 | out | Sony XAV-9500ES car head unit, automotive |
| 19 | CVE-2025-44018 | in | GL-Inet GL-AXT1800 travel router |
| 20 | CVE-2025-34053 | in | AVTECH IP cameras, DVR, NVR |
| 21 | CVE-2014-125122 | in | Linksys WRT120N router |
| 22 | CVE-2024-2022 | borderline | Netentsec NS-ASG application security gateway |
| 23 | CVE-2025-8757 | in | TRENDnet TV-IP110WN IP camera |
| 24 | CVE-2026-86509 | in | D-Link DIR-895L router |
| 25 | CVE-2026-27849 | in | Linksys mesh devices |
| 26 | CVE-2026-7719 | in | Totolink WA300 |
| 27 | CVE-2026-9407 | in | Totolink A8000RU router |
| 28 | CVE-2026-6168 | in | TOTOLINK A7000R router |
| 29 | CVE-2026-6114 | in | Totolink A7100RU router |
| 30 | CVE-2024-6108 | in | Genexis Tilgin home gateway |

## NVD-only calls

| # | CVE | Call | Why |
|---:|---|---|---|
| 1 | CVE-2023-21633 | out | Qualcomm modem interface layer, mobile |
| 2 | CVE-2002-2149 | in | Lucent Access Point service routers |
| 3 | CVE-2025-6733 | in | UTT HiPER 840G SMB router |
| 4 | CVE-2022-1038 | out | HP Jumpstart, PC software |
| 5 | CVE-2016-9371 | out | Moxa NPort, industrial serial device server |
| 6 | CVE-2022-22523 | out | Carlo Gavazzi UWP3.0, building and energy control |
| 7 | CVE-2026-3336 | out | AWS-LC, software library |
| 8 | CVE-2012-5037 | out | Cisco Catalyst 6500/7600, enterprise core switching |
| 9 | CVE-2019-15411 | out | Asus ZenFone, Android phone |
| 10 | CVE-2018-12198 | out | Intel Server Platform Services, server |
| 11 | CVE-2022-48454 | out | Unisoc Wi-Fi service, phone chipset |
| 12 | CVE-2024-37186 | in | Wavlink AC3000 router |
| 13 | CVE-2021-21880 | borderline | Lantronix PremierWave 2050, industrial wireless module |
| 14 | CVE-2015-6336 | borderline | Cisco Aironet 1800, enterprise access point |
| 15 | CVE-2021-20719 | borderline | Nippon Antenna RFNTPS, device type unclear |
| 16 | CVE-2015-8677 | out | Huawei S5300 campus switches, enterprise |
| 17 | CVE-2010-1563 | out | Cisco PGW 2200 softswitch, carrier |
| 18 | CVE-2026-20492 | out | MediaTek audio HAL, phone chipset |
| 19 | CVE-2022-46641 | in | D-Link DIR-846 router |
| 20 | CVE-2007-3441 | borderline | Aastra 9112i SIP phone |
| 21 | CVE-2023-38940 | in | Tenda F1203/FH1203/FH1205 routers |
| 22 | CVE-2023-37144 | in | Tenda AC10 router |
| 23 | CVE-2021-0146 | out | Intel processors |
| 24 | CVE-2007-4553 | borderline | Thomson ST 2030 SIP phone |
| 25 | CVE-2016-1158 | in | Corega CG-WLBARGMH/NL routers |
| 26 | CVE-2026-31058 | in | UTT HiPER 1200GW router |
| 27 | CVE-2019-10931 | out | Siemens SIPROTEC 5, industrial control |
| 28 | CVE-2022-45503 | in | Tenda W6-S access point |
| 29 | CVE-2019-5322 | out | Aruba enterprise switches |
| 30 | CVE-2006-4312 | borderline | Cisco PIX/ASA security appliances |

Nine of the 15 out-of-scope NVD-only records are from vendors on the curated
list's manual exclusions (Qualcomm, Cisco twice, Intel twice, Unisoc,
MediaTek, Moxa, Siemens). The NVD rule's hardware-CPE and firmware-suffix
clauses never consulted that list, which is the C4 fix. The other six (HP PC
software, Carlo Gavazzi, AWS-LC, an Asus phone, Huawei and Aruba enterprise
switches) are the kind a vendor list cannot reach, and records like them
remain in the corpus as a measured limitation.
