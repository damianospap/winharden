# Backlog

## A. Μηχανισμοί που δεν χρησιμοποιούνται (και γιατί)

| Μηχανισμός | Λόγος |
|---|---|
| `TurnOffWindowsCopilot` | Deprecated στο WindowsAI CSP και δεν αφορά την τρέχουσα εφαρμογή Copilot |
| `RemoveMicrosoftCopilotApp` | Τεκμηριώνεται για Enterprise, Education, IoT και όχι για Home (το Office Watch γράφει «Windows 11 Home is not supported either way»). Η registry τιμή δεν τεκμηριώνεται και ο πίνακας διαφωνεί με την περιγραφή. Digital Trends και Geekrewind αναφέρουν registry workaround για Home (κλειδί `WindowsAI`, τιμή `RemoveMicrosoftCopilotApp`): ανεπιβεβαίωτο, υποψήφιο για αποτροπή επανεγκατάστασης μόνο μετά από επαλήθευση σε VM. Στη θέση του: αφαίρεση του AppX (`ai-006`) |
| `RemoveDefaultMicrosoftStorePackages` | Η Microsoft την τεκμηριώνει για Enterprise και Education (25H2). Ένας οδηγός (allthings.how) γράφει ότι ισχύει και σε Pro και, με registry, σε Home («results may vary»), ενώ δύο άλλοι οδηγοί λένε το αντίθετο: ανεπιβεβαίωτο. Η v1 χρησιμοποιεί cmdlets, δες `docs/M4-CATALOG.md` |
| `AllowTelemetry=0` | Ισοδυναμεί με 1 εκτός Enterprise, Education και Server (Microsoft). Το `tel-001` γράφει 1 |
| Policies του WindowsAI χωρίς Home, όπως `DisableSettingsAgent` και agent connectors | Μόνο Enterprise, Education, IoT |
| Διαγραφή του DiagTrack | Μόνο Disabled. Αναφέρθηκε (δεν ξαναελέγχθηκε) ότι εργαλεία που τον διέγραψαν προκάλεσαν προβλήματα |
| Παρέμβαση σε Secure Boot | Never-touch: τα πιστοποιητικά του 2011 λήγουν μέσα στο 2026 |
| ETW tampering, firewall outbound default-deny | Εκτός v1 |
| Παρακάμψεις OOBE (τοπικός λογαριασμός, δίκτυο) | Εκτός πεδίου |
| `DisableSearchBoxSuggestions` | Τεκμηριώνεται μόνο για το search box του File Explorer, κλείνει και τις πρόσφατες αναζητήσεις του, και μία ανεπιβεβαίωτη αναφορά τη συνδέει με σπασμένο preview της κάμερας |
| Skipped στα M5, M6, M10 | WinRM off, FDResPub και fdPHost, IPv6 `DisabledComponents` (tunnel bits), Delivery Optimization, ενεργή διερεύνηση NCSI, Remote Assistance, Credential Guard, Smart App Control, αλλαγές στο BCD, αλλαγές στα πιστοποιητικά Secure Boot: λόγοι στο `docs/DECISIONS.md` D16 |
| Εγγραφή `1` στο `VulnerableDriverBlocklistEnable` | Μόνο attest (`plt-009`): η τιμή είναι στη never-touch λίστα, `docs/DECISIONS.md` D17 |
| `RunAsPPL=1` (με μεταβλητή UEFI) | Μόνο η τιμή 2, `docs/DECISIONS.md` D13 |
| Cloud block level `HighPlus` και `ZeroTolerance` | Το `def-008` γράφει `High`. Τα άλλα δύο αυξάνουν τα false positives και το `ZeroTolerance` μπλοκάρει όλα τα άγνωστα εκτελέσιμα |
| Αυτόματη αποστολή δειγμάτων του Defender | Μένει επιλογή του χρήστη (`def-028`), `docs/DECISIONS.md` D9 |
| Αυτόματη απεγκατάσταση OneDrive | Θέλει operation που τρέχει uninstaller τρίτου (έλεγχος υπογραφής και διαδρομής). Βλ. §C και `docs/DECISIONS.md` D18 |
| Απενεργοποίηση του Remote Desktop | Δεν ισχύει στο Home: δεν μπορεί να δεχτεί εισερχόμενες συνδέσεις RDP |
| WDAC και App Control, outbound default-deny, schannel και cipher suites, LAPS, webhook, αποκλεισμός δικτύου | Εκτός πεδίου από την αρχή, `docs/DECISIONS.md` D4 |

## B. Ανοιχτά σημεία επαλήθευσης (VM ή πραγματικό μηχάνημα)

- `tel-005`: η τιμή `Software\Microsoft\Input\TIPC\Enabled` προέρχεται από δευτερεύουσα πηγή. Επαλήθευση με registry diff του toggle.
- `ContentDeliveryManager`: οι τιμές `SubscribedContent-353694`, `-353696`, `-338388`, `-338389`, `-310093` και το `RotatingLockScreenEnabled` δεν μπήκαν μέχρι να φανεί στο diff ότι τις γράφει το Settings.
- Επιπλέον tasks προς εξέταση: `Autochk\Proxy`, `DiskDiagnostic`, `Device Information`, και το `QueueReporting` του WER.
- Policies `LimitDumpCollection` και `LimitDiagnosticLogCollection`.
- Policies του Edge και του Copilot στο Edge.
- Η εφαρμογή Microsoft 365 Copilot (`Microsoft.MicrosoftOfficeHub`) και οι εφαρμογές M365 Companion: στο M4, profile 2.
- `ai-005`: είναι η τιμή `Software\Microsoft\Windows\Shell\ClickToDo\DisableClickToDo` αυτή που γράφει το toggle του Settings; Το CSP αναφέρει μόνο Insider Preview ως εφαρμόσιμο OS.
- `ai-006`: το όνομα πακέτου `Microsoft.Copilot` προέρχεται μόνο από οδηγούς τρίτων.
- `ai-008`: υποψήφια τιμή για μηχανικό έλεγχο, `HKLM\SYSTEM\CurrentControlSet\Services\IsoEnvBroker\Enabled`. Δεν είναι βέβαιο ότι την γράφει το toggle. Η σελίδα της Microsoft γράφει «This is now available on preview builds 26100.7344+» και δεν αναφέρει Home ούτε σταθερά 25H2 ή 26H2: η διαθεσιμότητα του toggle στο Home είναι άγνωστη.
- `ai-009`: δεν βρέθηκε registry τιμή για τα toggles του Gaming Copilot, και οι πηγές διαφωνούν για τις προεπιλογές.
- M4: τα ανοιχτά σημεία επαλήθευσης σε VM (Weather και Widgets, Family Safety, δεδομένα Sticky Notes και To Do, ύπαρξη πακέτων σε 25H2 και 26H2) είναι στο `docs/M4-CATALOG.md`, ενότητα 8.
- Ισχυρισμός των σημειώσεων v1 ότι η Microsoft περιόρισε το Copilot σε Notepad, Snipping Tool και Photos (Μάρτιος 2026): η πηγή (Windows Latest) δεν ήταν προσβάσιμη. Δεν στηρίζεται σε αυτόν κανένα entry.

**M5, M6, M7, M9, M10 (ό,τι χρειάζεται VM ή πραγματικό μηχάνημα):**

- `plt-004`: δεν τεκμηριώνεται ότι το Home εκθέτει την κλάση WMI `Win32_EncryptableVolume` και κρυπτογραφεί τον δίσκο. Αν η κλάση λείπει, ο έλεγχος γίνεται χειροκίνητος.
- `plt-005`: ισχύει το ίδιο για το `Get-LocalUser` στο Home.
- `plt-008` (LSA protection): πριν από πραγματικό μηχάνημα, δες τα events 3033 και 3063 του CodeIntegrity. Στη VM: έλεγχος ότι το `lsass.exe` τρέχει ως protected process.
- `plt-009`: η τιμή `VulnerableDriverBlocklistEnable` ακολουθεί το toggle του Windows Security; Τι δείχνουν η τιμή και το toggle όταν το memory integrity είναι ενεργό;
- `plt-011` (memory integrity): η εγγραφή μόνο του `Enabled=1` αρκεί, χωρίς άλλες τιμές στο κλειδί `DeviceGuard`; Θέλει υλικό με virtualization. Έλεγχος: σύγκριση registry πριν και μετά το toggle του Settings.
- `plt-012` (Kernel DMA): δεν επαληθεύεται σε VM. Θέλει φυσικό PC με Kernel DMA Protection και εξωτερική συσκευή PCIe με μη συμβατό driver. Το όνομα της τιμής (`DeviceEnumerationPolicy`) προέρχεται από το STIG, όχι από τη σελίδα του CSP.
- M6: όλα τα `unverified` policy keys (`net-004`, `net-007`, `net-008`, `net-010`, `net-013`, `net-014`, `net-016`): αποτέλεσμα, όχι μόνο τιμή. Το `net-014` (mDNS) πηγαίνει πέρα από την κατεύθυνση της Microsoft.
- M7: τα `def-001` έως `def-010` γράφουν μέσω `Set-MpPreference`: έλεγχος ότι το `Get-MpPreference` επιστρέφει τις τιμές στο Home, και ότι ο Defender δεν έχει παραχωρήσει τον έλεγχο σε άλλο antivirus.
- M9: ο έλεγχος με `auditpol` τυπώνει μεταφρασμένο κείμενο και παραλείπεται όταν η γλώσσα εμφάνισης δεν είναι αγγλικά (ισχύει και για ελληνικά Windows): ο έλεγχος κατάστασης καλύπτει την ίδια ρύθμιση. Στη VM: έλεγχος της στήλης «Inclusion Setting». Επίσης: αν μια παλιά πολιτική κατηγορίας υπερισχύει των subcategories (`SCENoApplyLegacyAuditPolicy`, γενική γνώση, δεν ελέγχθηκε σε πηγή), τα `aud-*` δεν θα έχουν αποτέλεσμα.
- M10: αν το Home διαβάζει τα `DisableFileSyncNGSC`, `DisablePersonalSync` και `KFMBlockOptIn` χωρίς Group Policy. Αν όχι, το μόνο που μένει είναι η απεγκατάσταση (`one-004`).
- Καμία ρύθμιση που προϋποθέτει υλικό (memory integrity, Kernel DMA, Secure Boot, TPM) δεν δοκιμάστηκε σε φυσικό PC.

### Ποιότητα πηγών (να γίνει πριν από τη VM)

- Το WebFetch επιστρέφει περίληψη από μικρό μοντέλο και μπορεί να επινοήσει: για το Manage Recall επινόησε στήλη «Editions: Not restricted», που είχε περάσει στα `ai-001` και `ai-002` και διορθώθηκε. Κάθε παράθεση πρέπει να ζητιέται αυτολεξεί και να συγκρίνεται με το κείμενο του entry.
- M3: όλες οι παραθέσεις ξαναελέγχθηκαν αυτολεξεί σε δεύτερο γύρο. Ένα snippet αναζήτησης (WindowsForum) αφαιρέθηκε επειδή δεν ήταν επαληθεύσιμο, και ένα test απαγορεύει πλέον πηγές τύπου snippet.
- M4 κατάλογος: οι S1, S3 και S4 ξαναδιαβάστηκαν στις 2026-11-12 για έλεγχο ονομάτων, ενοτήτων, τιμών και παραθέσεων, και συμφωνούν (εξαίρεση: ένα όνομα εκτός καταλόγου στην S4, βλ. `docs/M4-CATALOG.md`, ενότητα 1). Η S2 δεν ξαναδιαβάστηκε σε αυτό το βήμα.
- M1 (28 evidence items) και M2 (27) γράφτηκαν από περιληπτικές λήψεις και δεν έχουν ξαναελεγχθεί αυτολεξεί. Τα 8 από αυτά είναι ρητά `background` («prior knowledge, not re-verified»).
- Ο ανεξάρτητος έλεγχος γεγονότων από ξεχωριστό agent δεν ολοκληρώθηκε (όριο χρήσης). Ό,τι ελέγχθηκε, ελέγχθηκε από μένα με αυτολεξεί λήψεις.

- M5, M6, M10 (2026-11-15 και 16): οι σελίδες διαβάστηκαν με το ίδιο εργαλείο περίληψης. Σε εισαγωγικά μπήκε μόνο ό,τι επέστρεψε σε εισαγωγικά, τα υπόλοιπα είναι παράφραση, και ό,τι είναι γενική γνώση φέρει βαθμό `background`. Δεν έγινε δεύτερος αυτολεξεί έλεγχος των παραθέσεων, όπως στο M3.
- Όπου μια σελίδα της Microsoft δεν κατονομάζει το Home, το entry έχει εγγραφή `ms-doc-nonhome` και είναι `unverified`.

## C. Σχεδιαστικά ανοιχτά

Έκλεισαν: το πεδίο `requires_hardware` υλοποιείται (D6), το feature που λείπει θεωρείται συμμορφωμένο, και ο engine υπάρχει (preflight, plan, journal, apply, verify, rollback, αναφορές, drift task, selftest).

Ανοιχτά:

- **Ο engine έχει τρέξει μόνο σε μία VM.** Έτρεξαν `selftest`, `plan`, `apply -Profile 3`, `verify` και, στις 2026-11-23 και σύμφωνα με τον χρήστη, το `rollback` (χωρίς καταγραμμένη έξοδο). Πρώτο και κύριο βήμα: `docs/VERIFY-PROTOCOL.md`, ενότητα 0 (τι βρέθηκε μέχρι τώρα: `docs/DECISIONS.md` D20, D21 και D22· η D21 επιβεβαιώθηκε στη VM στις 2026-11-23). Ανοιχτό: οι εξαιρέσεις στο ownership του `apply` (δεν έχουν καταγραφεί) και η έξοδος του `rollback` (checkpoint, πόσες αλλαγές αναιρέθηκαν, ποια entries βγήκαν `partial`, και αν το `plan -Profile 3` μετά ξαναέδειξε τις αλλαγές).
- **Τα `appx-006` και `appx-007` δεν ήταν FAIL στο πρώτο `verify` του `apply -Profile 3` και είναι στο επόμενο.** Δεν ξέρω αν τότε είχαν αφαιρεθεί (με `-AcceptDataLoss`) και ήρθαν πίσω, ή αν άλλαξε η VM (snapshot). Χρειάζεται η γραμμή του `apply` για αυτά τα δύο (`applied`, `FAILED` ή `blocked`).
- **Ανεξάρτητη αναθεώρηση του engine** από άνθρωπο που ξέρει PowerShell 5.1 (provider real, journal, rollback). Δεν έγινε.
- Operation που τρέχει vendor uninstaller με έλεγχο υπογραφής και διαδρομής, ώστε το `one-004` να γίνει αυτόματο. Είναι η μεγαλύτερη μη δοκιμασμένη επιφάνεια που θα προσθέταμε.
- Διαχείριση μεγέθους και διατήρησης των logs που ενεργοποιεί το M9 (Security, PowerShell Operational), και PowerShell module logging: δεν υπάρχουν.
- Έλεγχος κατάστασης για τιμές HKCU όταν το εργαλείο τρέχει ως SYSTEM (ισχύει μόνο για το drift task): καλύπτεται από τον έλεγχο κατάστασης κάθε profile, αλλά δεν έχει δοκιμαστεί.
- Cleanup: το παράθυρο TOCTOU ανάμεσα στην απαρίθμηση και στη διαγραφή (`docs/THREAT-MODEL.md` §4).
- Εγγραφές `attest` και `manual` είναι υποχρεωμένες να έχουν `rollback` χωρίς να αλλάζουν κάτι: να χαλαρώσει ο κανόνας ή να μείνει ως έχει.

## D. Επόμενα βήματα

1. VM Windows 11 Home 25H2 με snapshot: το `verify -Profile 3` με τη διόρθωση της D21 έγινε στις 2026-11-23 και τα 29 ERROR έφυγαν. Το `rollback` του ίδιου run έγινε στις 2026-11-23 και ο χρήστης το ανέφερε σωστό. Μένει να καταγραφεί η έξοδός του και το `plan -Profile 3` μετά από αυτό, που πρέπει να ξαναδείξει τις αλλαγές του αρχικού plan εκτός από όσες είναι `partial`. Μετά: διόρθωση ό,τι βρεθεί στον engine. Δεν έχει επιβεβαιωθεί ακόμη ότι το νέο test του `verify` (D22) πέρασε σε Windows: το τρέχει η πύλη του `apply`.
2. `plan` και `apply` ανά profile σύμφωνα με το `docs/VERIFY-PROTOCOL.md`, ένα entry τη φορά για τα `unverified`.
3. Καταγραφή `verified` (ή αφαίρεση του entry αν δεν κάνει τίποτα) και ενημέρωση του `docs/REFERENCE.md`.
4. Έλεγχος σε πραγματικό PC για ό,τι θέλει υλικό (memory integrity, Kernel DMA, Secure Boot, TPM, BitLocker).
5. Δοκιμή drift με in-place αναβάθμιση 25H2 σε 26H2.
