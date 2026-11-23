# Πρωτόκολλο επαλήθευσης σε Windows 11 Home

Σκοπός: να μετατραπεί ένα entry από `unverified` ή `expected` σε `verified` με παρατήρηση, όχι με υπόθεση. Αυτό είναι το μόνο βήμα που δεν μπορεί να γίνει από τον κώδικα: χρειάζεται VM ή μηχάνημα με Windows 11 Home.

## 0. Πρώτη εκτέλεση του engine

**Ο engine έχει τρέξει μόνο σε μία VM Windows 11 Home.** Το `selftest` και το `plan` έτρεξαν, η πύλη του `apply` βρήκε τρία λάθη του ίδιου του selftest (`docs/DECISIONS.md` D20), και μετά τη διόρθωση έτρεξε το `apply -Profile 3` με `verify` στο τέλος, όπου 29 audits δεν μπόρεσαν να τρέξουν. Η διόρθωση D21 επιβεβαιώθηκε στη VM στις 2026-11-23: τα 29 δεν είναι πια ERROR. Το ίδιο `verify` έδειξε FAIL στα `appx-006` και `appx-007`, γιατί το `apply` δεν τα αφαιρεί χωρίς `-AcceptDataLoss` (D22). Στις 2026-11-23 έτρεξε και το `rollback` του πρώτου run: ο χρήστης ανέφερε ότι ήταν σωστό, αλλά η έξοδός του δεν έχει καταγραφεί. Πριν από οποιαδήποτε επαλήθευση entry, πρέπει να αποδειχθεί ότι ο ίδιος ο engine δουλεύει. Όλα εδώ γίνονται σε VM με snapshot, όχι στο μηχάνημα που χρησιμοποιείς.

1. Προετοιμασία της VM όπως στην ενότητα 1, και baseline όπως στην ενότητα 2.
2. Άνοιξε Windows PowerShell 5.1 (`powershell.exe`, 64-bit) ως Administrator, στον φάκελο του project.
3. `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 selftest`. Αναμενόμενο: όλοι οι έλεγχοι περνούν και δεν αλλάζει τίποτα στο σύστημα. Αν αποτύχει κάποιος, κράτα όλη την έξοδο μαζί με το `code fingerprint` της πρώτης γραμμής: είναι σφάλμα του engine. Το `-SkipSelfTest` δεν είναι λύση σε πραγματικό μηχάνημα.
4. `status`, `list -Profile 3` και `plan -Profile 1`: μόνο ανάγνωση. Έλεγξε ότι το plan συμφωνεί με το `docs/REFERENCE.md` και με όσα βλέπεις στη VM (τιμές «πριν»).
5. `apply -Profile 1`: διάβασε το plan, έγκρινε. Σε VM χωρίς TPM 2.0 ή Secure Boot πρόσθεσε `-AllowPlatformGaps`: τα entries που τα χρειάζονται μένουν μπλοκαρισμένα και δεν δοκιμάζονται εκεί. Μετά `verify`, άνοιξε την αναφορά HTML και το JSON στο `%ProgramData%\winharden\reports\<run>`, και τρέξε τα golden checks της ενότητας 3.
6. `checkpoints` (επαληθεύει και το journal), μετά `rollback -To latest`, και σύγκριση με το baseline: πρέπει να επανέλθουν όλα εκτός από όσα δηλώνουν `partial` και `limitation`.
7. Επανάλαβε με `-Profile 2` και `-Profile 3` (και `-OptIn` για τα opt-in entries), πάντα από το snapshot και με την ίδια σειρά: plan, apply, verify, golden checks, rollback, σύγκριση.
8. Κάθε αποτυχία (`exit code` 1 ή 3, σφάλμα PowerShell, τιμή που δεν γράφτηκε, rollback που δεν επανέφερε) καταγράφεται με: εντολή, έξοδο, `%ProgramData%\winharden\logs` και το fingerprint.

Μόνο όταν τα βήματα 3 έως 7 περάσουν σε καθαρή VM έχει νόημα η επαλήθευση ενός entry.

## 1. Προετοιμασία

1. Δύο VMs (VirtualBox ή VMware): Windows 11 Home **25H2** (build 26200.x) και **26H2** (build 26300.x), με vTPM και Secure Boot όπου το επιτρέπει ο hypervisor.
2. Εγκατάσταση, όλα τα updates, επανεκκίνηση, και snapshot `clean-baseline`.
3. Αντίγραψε το project στη VM. Δεν χρειάζεται δίκτυο για το εργαλείο· το δίκτυο χρειάζεται μόνο για τον έλεγχο του Windows Update.

## 2. Baseline (μόνο ανάγνωση)

Σε PowerShell ως διαχειριστής, φάκελος `baseline\`:

```powershell
Get-Service | Select-Object Name,StartType,Status | Sort-Object Name | Export-Csv baseline\services.csv -NoTypeInformation
Get-ScheduledTask | Select-Object TaskPath,TaskName,State | Sort-Object TaskPath,TaskName | Export-Csv baseline\tasks.csv -NoTypeInformation
Get-AppxPackage -AllUsers | Select-Object Name,PackageFullName | Sort-Object Name | Export-Csv baseline\appx.csv -NoTypeInformation
Get-AppxProvisionedPackage -Online | Select-Object DisplayName | Sort-Object DisplayName | Export-Csv baseline\provisioned.csv -NoTypeInformation
Get-WindowsOptionalFeature -Online | Select-Object FeatureName,State | Sort-Object FeatureName | Export-Csv baseline\features.csv -NoTypeInformation
reg export HKLM\SOFTWARE\Policies baseline\hklm-policies.reg /y
reg export HKCU\Software baseline\hkcu-software.reg /y
```

## 3. Golden checks (μόνο ανάγνωση, πριν και μετά)

Τα αποτελέσματα πρέπει να είναι **ίδια** πριν και μετά από κάθε entry.

| Έλεγχος | Εντολή ή ενέργεια |
|---|---|
| Windows Update σαρώνει | `(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count` ολοκληρώνεται χωρίς σφάλμα |
| Store | `Get-AppxPackage -AllUsers Microsoft.WindowsStore` υπάρχει |
| App Installer | `winget --version` δουλεύει |
| Defender | `Get-MpComputerStatus` δίνει τα ίδια `AMServiceEnabled`, `RealTimeProtectionEnabled`, `IsTamperProtected` |
| Υγεία του component store | `DISM /Online /Cleanup-Image /CheckHealth` χωρίς πρόβλημα |
| Device Encryption | Ίδια κατάσταση στο Settings > Privacy & security > Device encryption |
| Secure Boot | Ίδιο αποτέλεσμα στο `Confirm-SecureBootUEFI` (σε VM μπορεί να μην υποστηρίζεται: σημείωσέ το) |
| Υπόλοιπο σύστημα | Τα CSV του baseline διαφέρουν **μόνο** στα στοιχεία που αγγίζει το entry |

## 4. Διαδικασία ανά entry (ένα τη φορά)

1. Επαναφορά στο snapshot `clean-baseline`, νέο baseline.
2. Εφαρμογή **μόνο** του entry: `plan -Profile 3 -Only <id>` και μετά `apply -Profile 3 -Only <id>` (με `-OptIn <όνομα>` για opt-in entries, `-AcceptDataLoss` για entries που σβήνουν δεδομένα). Αν δεν δουλεύει ο engine, με το χέρι ακριβώς όπως δηλώνει το `apply` του entry.
3. Επανεκκίνηση αν το entry έχει `requires_reboot`.
4. Τρέξε τα `audit.checks`: πρέπει να δίνουν το `expected`.
5. Κοίτα το **αποτέλεσμα**, όχι μόνο την τιμή: το toggle στο Settings είναι κλειδωμένο ή Off, η εφαρμογή ή το feature εξαφανίστηκε, η υπηρεσία είναι Disabled, κ.ο.κ.
6. Golden checks και σύγκριση CSV με το baseline.
7. Rollback και σύγκριση με το baseline: πρέπει να επανέλθουν όλα εκτός από όσα δηλώνει το `limitation`.
8. Καταγραφή (ενότητα 6).

## 5. Τιμές που γράφει το Settings (settings-backing)

Για κάθε τιμή HKCU που προέρχεται από κοινότητα, βρες αν την γράφει πραγματικά το Settings:

```
reg export HKCU\Software before.reg /y
(άλλαξε το toggle στο Settings)
reg export HKCU\Software after.reg /y
Compare-Object (Get-Content before.reg) (Get-Content after.reg)
```

Αν η τιμή δεν εμφανίζεται στη διαφορά, **σβήσε την** από το entry. Αν εμφανίζεται άλλη τιμή, πρόσθεσέ την με σημείωση για την πηγή.

## 6. Καταγραφή

Στο entry: `home_effective: "verified"` και

```json
"verified": {
  "build": "10.0.26200.xxxx",
  "date": "2026-11-20",
  "vm": "VirtualBox 7.x, Windows 11 Home 25H2",
  "observed": "Τι είδες ακριβώς: τιμή στο registry, κατάσταση του toggle, αποτέλεσμα στο UI"
}
```

Μετά τρέξε `python3 -I tools/validate_manifests.py` (ο R05 απαιτεί το αντικείμενο `verified`) και `python3 -I tools/gen_reference.py`.

Κανόνες:

- Το `verified` προϋποθέτει: audit ΟΚ, παρατηρήσιμο αποτέλεσμα, golden checks αμετάβλητα, rollback ΟΚ.
- Αν η ρύθμιση δεν κάνει τίποτα (vestigial), **αφαίρεσε το entry** και γράψε τον λόγο στο `docs/BACKLOG.md`.
- Entries που χρειάζονται Copilot+ υλικό (Recall, Click to Do) δεν επαληθεύονται σε VM. Επαλήθευσέ τα σε πραγματικό μηχάνημα και γράψε το μοντέλο στο πεδίο `vm`. Στη VM ελέγχονται μόνο η εγγραφή στο registry και το audit.

## 7. Δοκιμή drift στην αναβάθμιση

1. Επαλήθευσε όλα τα entries στο 25H2.
2. Κάνε in-place αναβάθμιση της VM στο 26H2 (από snapshot).
3. Τρέξε μόνο έλεγχο (verify): κάθε entry που αποτυγχάνει είναι drift.
4. Για κάθε drift: ενημέρωσε το entry ή πρόσθεσε ξεχωριστό για το 26H2, και ξαναγράψε τα `verified`.

Το ίδιο ισχύει για κάθε νέο cumulative update. Το `install-drift` εγκαθιστά task που τρέχει αυτόν τον έλεγχο εβδομαδιαία και σε κάθε εκκίνηση, και γράφει αναφορά. Δοκίμασέ το στη VM: `install-drift`, αλλαγή ενός entry με το χέρι, επανεκκίνηση, και έλεγχος ότι η αναφορά το δείχνει ως drift. Το `remove-drift` (με `-RemoveFiles`) το αφαιρεί.

## 8. Έλεγχοι που θέλουν υλικό (πραγματικό PC)

Η VM δεν αρκεί για τα παρακάτω. Σημείωσε το μοντέλο του μηχανήματος στο πεδίο `vm` του `verified`.

| Entry | Τι ελέγχεται | Πώς |
|---|---|---|
| `plt-001`, `plt-003` | Secure Boot και πιστοποιητικά 2023 | `Confirm-SecureBootUEFI` (True), msinfo32 «Secure Boot State», και η τιμή `UEFICA2023Status` μετά τα updates του 2026 |
| `plt-002`, `plt-004` | TPM 2.0 και κρυπτογράφηση συστήματος | Windows Security > Device security > Security processor details, και Settings > Privacy & security > Device encryption |
| `plt-008` | LSA protection | Πριν: events 3033 και 3063 στο CodeIntegrity Operational. Μετά την επανεκκίνηση: το `lsass.exe` τρέχει ως protected process και τίποτα που χρειάζεσαι δεν σταμάτησε |
| `plt-011` | Memory integrity | Μετά την επανεκκίνηση: `Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard`, το `SecurityServicesRunning` περιέχει 2. Το Windows Security > Core isolation δείχνει On. Έλεγχος ότι οι drivers σου δεν μπλοκάρονται |
| `plt-012` | Kernel DMA block-all | msinfo32 «Kernel DMA Protection: On». Σύνδεση εξωτερικής συσκευής PCIe με συμβατό και με μη συμβατό driver |
| M7 | Defender | Σε PC χωρίς άλλο antivirus: `Get-MpPreference` και `Get-MpComputerStatus` δείχνουν τις τιμές των entries |
