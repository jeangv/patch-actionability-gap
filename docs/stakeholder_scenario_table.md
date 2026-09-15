# Defender Scenario Table (Week 3, W3.1)

Expands PR1's five-row stakeholder/responsibility table (Problem Statement
section) into the full defender scenario table: update mechanism, what each
class actually knows about its devices, what tooling it has, and an explicit
out-of-scope row. Adds the field-level identifiability column requested by
peer review AD-3 (D8): record-level identifiability (does the CVE record
specify a firmware version) is necessary but not sufficient -- a defender
also has to be *able to query* their installed firmware version off the
device itself, and that capability varies sharply by ownership class.

| Device Owner | Update mechanism | What this class knows about its devices | Tooling available | Can this class determine its installed firmware version? (field-level identifiability) | Principal obstacle |
|---|---|---|---|---|---|
| **Household consumer** | Manual, via a web-based admin UI on the device (or automatic when the ISP owns the gateway) | Model number at best (on a physical label); firmware version only if they open the admin UI, which most never do | None -- no scanner, no asset inventory, no vulnerability feed | **No, in practice.** The firmware version is visible in the admin UI, but the owner has no reason to look and no notification tells them to. Physical labels do not update when firmware does, so a label-based check is unreliable for firmware version specifically (only model). | No notification when an advisory publishes; updates are behind a menu that is rarely opened |
| **Small and medium business** | An IT generalist or outside contractor logs into each device's admin UI manually; no fleet management | Device models are known informally (whoever bought it remembers); firmware versions are not tracked anywhere | A vulnerability scanner may run, but with no asset inventory to cross-reference against | **Partially.** The admin UI exposes firmware version like the consumer case, but nobody is assigned to check it, and a scanner finding gives a CVE ID with no indication of which of the org's devices (if any) is the named model/version | No asset inventory listing device models and firmware versions; scanner findings arrive with no fix-exists signal |
| **ISP / managed service provider** | Remote, provider-controlled, over TR-069 (CWMP) or a successor management protocol, on the provider's own release schedule | Full inventory -- the provider knows exactly which model and firmware build every leased device is running, because it manages the device remotely | Fleet management platform (TR-069 ACS or equivalent); this is the one class with real tooling | **Yes**, directly and completely -- this is the one ownership class where identifiability is a non-issue | The vendor's fix must be qualified into the provider's own validated firmware build before it can be pushed; the subscriber cannot act independently, and the provider's own release cadence -- not CVE publication -- sets the timeline |
| **Enterprise with unmanaged (shadow-IT) devices** | The security team can push updates only for devices already in the asset inventory; anything else is invisible until discovered | Unknown until a network scan or manual audit finds the device -- cameras, NAS, and gateways are routinely procured outside IT | Enterprise vulnerability scanner and asset-management platform, but only effective for what is already inventoried | **No, for the shadow-IT subset** -- by definition, if IT does not know the device exists, no field-level check is possible; once discovered, identifiability matches whatever the CVE record itself provides | Devices procured outside IT (cameras, NAS, gateways) are invisible to the security team until a scan discovers them |
| **End-of-life or abandoned device** | None -- the vendor has exited support for the model; no update channel exists at all, regardless of what the CVE record says | Whatever the owner (in one of the four classes above) already knew before support ended -- EOL status is not itself signaled by the CVE record | Same as whichever ownership class above happens to hold the device -- EOL status is a property of the *model*, not of the finding | **Irrelevant.** Even a perfectly identifiable, perfectly fix-available record cannot be acted on, because no fix will ever be produced for this model | No fix will be produced; the only available responses are mitigation or replacement, neither of which severity-based tooling recommends |
| **Out of scope** *(new row)* | -- | -- | -- | -- | Devices excluded from this study's corpus by the Appendix B soft-exclusion categories -- enterprise datacenter/server platforms, ICS, medical devices, automotive systems, mobile handsets, general-purpose computers -- are out of scope not because their patch-actionability problem doesn't exist, but because each operates under a different disclosure/regulatory regime (ICS: ISA/IEC 62443 and CISA ICS-CERT; medical: FDA premarket cybersecurity guidance; automotive: UNECE R155) that would confound a single vendor comparison across categories. This study's findings should not be generalized to those categories without separate validation. |

## What this table answers for the security-relevance argument

This table is what PR1's stakeholder-analysis section pointed to but did not
fully spell out: the three actionability dimensions are not abstract data-
quality measures, they are the literal precondition for each class's own
update mechanism to function. An ISP cannot act on fix-availability alone --
it needs the fix *and* time to qualify it into a validated build; a household
consumer cannot act on a perfect CVE record at all, because nothing in the
record reaches the one place (the admin UI) where they would ever see it.
The field-level identifiability column makes explicit what AD-3 pointed out
in peer review: record-level identifiability is necessary but not sufficient
for three of the five classes.
