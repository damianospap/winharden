# Αποφάσεις που πήρα χωρίς να ρωτήσω

Στις 2026-11-13 ζήτησες: «Μην με ρωτάς, τελείωσε όλο το εργαλείο», με στόχο τα πιο καθαρά, ιδιωτικά και ασφαλή Windows, ακόμα και με πολύ επιθετικό debloating, και με τις προϋποθέσεις της αρχικής προδιαγραφής. Εδώ γράφω κάθε απόφαση που αλλιώς θα σου την έθετα ως ερώτηση: τι διάλεξα, γιατί, και πώς την αλλάζεις αν διαφωνείς.

Ισχύουν πάντα οι κανόνες της προδιαγραφής: declarative και idempotent, per-line accountability, supported channels πρώτα, αναστρεψιμότητα ή ρητό όριο, never-touch λίστα, plan πριν την εφαρμογή. Το «επιθετικό» σημαίνει περισσότερες και βαθύτερες ρυθμίσεις στο profile 3, **όχι** χαλάρωση αυτών των κανόνων.

## D1. M4 AppX: 30 entries (3 / 10 / 17)

Ο κατάλογος του `docs/M4-CATALOG.md` είχε 23 πακέτα (3 / 10 / 10). Πρόσθεσα 7 πακέτα στο profile 3: Tips (`Microsoft.Getstarted`), 3D Viewer, Mixed Reality Portal, Skype, OneNote για Windows 10, Cortana (`Microsoft.549981C3F5F10`) και Xbox Console Companion (`Microsoft.XboxApp`).

- **Γιατί:** το «πολύ επιθετικό debloating» ζητά και τα παλιά πακέτα που υπάρχουν σε συστήματα που αναβαθμίστηκαν από προηγούμενες εκδόσεις. Κάθε ένα είναι στην S3 (Win11Debloat, ενότητα 1) και στην S4 (tiny11builder), άρα ικανοποιεί τον κανόνα «δύο πηγές».
- **Κόστος:** σε καθαρή εγκατάσταση 25H2 πιθανότατα λείπουν, και τότε το entry είναι no-op (το πακέτο που λείπει θεωρείται συμμορφωμένο). Δεν επαληθεύτηκε σε VM.
- **Αλλαγή:** σβήσε το entry από το `manifests/m4-appx.json` και ξαναγράψε το `docs/REFERENCE.md` (`python3 -I tools/gen_reference.py`).

## D2. Τα τρία πακέτα Xbox μένουν εκτός

`Microsoft.Xbox.TCUI`, `Microsoft.XboxIdentityProvider`, `Microsoft.XboxSpeechToTextOverlay`. Η Microsoft τα έχει `true` στο δικό της sample, αλλά:

- Για το `Xbox.TCUI` η S3 γράφει «UI framework, seems to be required for MS store, photos and certain games». Το Store είναι στη never-touch λίστα, άρα δεν παίρνω ρίσκο που μπορεί να το σπάσει.
- Για το `XboxSpeechToTextOverlay` η S3 γράφει «WARNING: This app cannot be reinstalled!». Το έργο υπόσχεται αναστρεψιμότητα ή ρητό όριο, και ένα μη αναστρέψιμο entry με αμελητέο όφελος (overlay φωνής μέσα σε παιχνίδια) δεν αξίζει.
- Το `XboxIdentityProvider` είναι το πλαίσιο σύνδεσης της στοίβας Xbox. Αφού αφαιρούνται οι εφαρμογές Xbox στο profile 3, μένει ανενεργό και η αφαίρεσή του προσθέτει μόνο ρίσκο.

Ένα test (`test_xbox_packages_that_other_components_may_need_stay_out`) το επιβάλλει. **Αλλαγή:** αφαίρεσε το όνομα από το σύνολο του test και πρόσθεσε entry με `risk: high` και `rollback.limitation` που να λέει ρητά τι δεν επανέρχεται.

## D3. Sticky Notes και To Do: profile 2, με πύλη για απώλεια δεδομένων

Έμειναν στο profile 2, αλλά πρόσθεσα στο schema το `flags.deletes_user_data` και τον κανόνα R18. Ένα entry με αυτό το flag πρέπει να είναι `enforce` και το πολύ `partial` στο rollback. Ο engine το παραλείπει εκτός αν το plan φτιάχτηκε με `-AcceptDataLoss`, και το plan το δείχνει σε ξεχωριστή ενότητα.

- **Γιατί:** η αφαίρεση του πακέτου σβήνει τις τοπικές σημειώσεις και λίστες (υπόθεση: η Microsoft Learn δεν λέει τι γίνεται με τα δεδομένα). Η απώλεια πρέπει να είναι συνειδητή επιλογή, όχι παρενέργεια.
- **Εκτός πύλης το Recall:** οι ρυθμίσεις `ai-001`, `ai-002`, `ai-003` σβήνουν τα snapshots του Recall (τεκμηριωμένο από τη Microsoft). Δεν τις έβαλα στο flag, γιατί η προδιαγραφή λέει ότι το Recall **πρέπει** να είναι απενεργοποιημένο και βεβαιωμένο σε κάθε profile. Η απώλεια των snapshots είναι το επιδιωκόμενο αποτέλεσμα της ιδιωτικότητας και δηλώνεται στο `impact` και στο `rollback.limitation`.
- **Αλλαγή:** αφαίρεσε το flag από το entry (και μετακίνησέ το σε profile 3 αν θες να μη φαίνεται σε profile 2).

## D4. Τι σημαίνει «επιθετικό» και «τέλειο hardening»

- **Τι διάλεξα:** το profile 3 είναι το βαθύ: 51 entries με `min_profile 3` (οι περισσότεροι ASR κανόνες σε block, Controlled Folder Access, Network Protection, πολιτική audit και script block logging, memory integrity, Kernel DMA block-all, UAC «always notify», SMB server signing, NTLMv2 μόνο, mDNS και SSDP off, Windows Script Host off, κ.ά.), και 5 entries πίσω από ρητό `-OptIn` (spooler, υπηρεσία Server, τρία για το OneDrive). Ό,τι δεν είναι αναστρέψιμο ή δεν έχει υποστηριζόμενο κανάλι μένει `manual`, `opt_in` ή εκτός.
- **Παραμένουν εκτός** (ήταν εκτός από την αρχή): WDAC και App Control, outbound default-deny στο firewall, ρύθμιση schannel και cipher suites, παρέμβαση σε ETW, LAPS, webhook, αποκλεισμός δικτύου. Λόγος: δεν υπάρχει υποστηριζόμενο κανάλι σε Home, ή το ρίσκο δεν αναιρείται αξιόπιστα, ή θα έκανε το εργαλείο over-engineered, που είπες ότι δεν θες.
- **Τέλειο hardening δεν μπορώ να υποσχεθώ:** τίποτα δεν έχει επαληθευτεί σε Windows 11 Home (κανένα entry δεν είναι `verified`) και 43 από τα 133 entries είναι `unverified`. Το εργαλείο λέει στην αναφορά τι εφαρμόστηκε και τι όχι, και ποια χάσματα μένουν.
- **Αλλαγή:** μετακίνησε `min_profile` ή `risk` στο manifest (το `risk` δένεται με το `min_profile` από τον κανόνα R16).

## D5. Ο engine: σχεδιασμός

- **Τι διάλεξα:** Windows PowerShell 5.1, μόνο ASCII, χωρίς εξαρτήσεις και χωρίς δίκτυο. Ο ίδιος κώδικας τρέχει πάνω σε `real` provider (registry, υπηρεσίες, tasks, AppX, optional features, Defender, auditpol) ή σε `fake` provider στη μνήμη (το `selftest`). Το journal είναι append-only με HMAC-SHA256 ανά εγγραφή και αλυσίδα, write-ahead: η προηγούμενη κατάσταση γράφεται πριν από κάθε αλλαγή. Κάθε entry είναι ένα transaction: αν αποτύχει οποιοδήποτε βήμα, επαναφέρονται όσα είχαν ήδη αλλάξει. Το plan έχει hash και η έγκριση δένεται σε αυτό (`-Yes -PlanId`). Ένας κύκλος τη φορά ανά μηχάνημα (mutex).
- **Γιατί:** το rollback γίνεται από όσα καταγράφηκαν πριν την αλλαγή, όχι από όσα «πρέπει» να είναι. Το fake provider επιτρέπει να δοκιμάζονται η λογική του plan, η αναίρεση και οι πύλες χωρίς να αγγίξει κανείς σύστημα.
- **Όριο:** το HMAC είναι tamper-evidence απέναντι σε οτιδήποτε δεν είναι διαχειριστής. Ένας διαχειριστής μπορεί να ξαναγράψει και το κλειδί και το journal (`docs/THREAT-MODEL.md`).
- **Πύλη selftest:** πριν από κάθε `apply` ο engine τρέχει τα δικά του tests πάνω στο fake σύστημα. Αν αποτύχει, δεν αγγίζει το σύστημα. Αν το selftest αποτύχει λανθασμένα (το έχει κάνει ήδη μία φορά: D20), το `-SkipSelfTest` το παρακάμπτει. Δες την ειλικρινή κατάσταση στο `README.md`.

## D6. Το `requires_hardware`

- **Τι διάλεξα:** το πεδίο υλοποιείται, ένα token ανά entry. Ο engine ξέρει `secure_boot`, `tpm2`, `virtualization`, `uefi` και `defender_active`. Αν λείπει η απαίτηση, το plan δείχνει το entry ως `blocked` με τον λόγο και ο engine δεν το εφαρμόζει· η υπόλοιπη εκτέλεση συνεχίζεται. Όλα τα entries του M7 απαιτούν `defender_active`, γιατί οι προτιμήσεις του Defender δεν έχουν αποτέλεσμα όταν άλλο antivirus είναι ενεργό. Το `memory-integrity` (M5) απαιτεί `virtualization`. Ένα test ελέγχει ότι κάθε τιμή που χρησιμοποιείται υλοποιείται από τον engine.
- **Αλλαγή:** αφαίρεσε το πεδίο από το entry (και δες στο notes αν χρειάζεται άλλο μέτρο).

## D7. Νέα είδη operations και το mode `once`

- **Τι διάλεξα:** `setting` (με `kind` `defender_pref`, `defender_asr` ή `audit_policy`) και `file_cleanup`. Και τα δύο έχουν allow-list στο `policy/never-touch.json`: το εργαλείο γράφει μόνο τιμές που αναφέρονται εκεί (το Defender μόνο προς το ασφαλέστερο, το audit μόνο Success και Failure, ο καθαρισμός μόνο στις ρίζες που αναφέρονται και μόνο αρχεία παλαιότερα από μία ημέρα). Ένα test απαιτεί η allow-list να περιέχει ακριβώς όσα χρησιμοποιούν τα manifests, τίποτα «για αργότερα».
- **Mode `once`:** τα entries καθαρισμού (M8) εκτελούνται μία φορά και το verify δεν τα θεωρεί drift. Το rollback τους είναι πάντα `partial`: τα αρχεία που διαγράφηκαν δεν επανέρχονται.

## D8. Η βαθμίδα opt-in

- **Τι διάλεξα:** το πεδίο `opt_in` βάζει ένα entry εκτός κάθε profile, εκτός αν η εκτέλεση το ζητήσει με `-OptIn <όνομα>`. Χρησιμοποιείται για αλλαγές που είναι σωστές για μερικούς μόνο: `no-printing` (υπηρεσία Print Spooler), `no-file-sharing` (υπηρεσία Server), `no-onedrive` (τρία entries). Όλα είναι profile 3 και με ρίσκο `medium` ή `high`.
- **Αλλαγή:** αφαίρεσε το `opt_in` από το entry για να μπει στο profile 3 χωρίς flag.

## D9. Το Defender: ασφάλεια πάνω από ιδιωτικότητα, και τι μένει στον χρήστη

- **Τι διάλεξα:** το `def-001` κρατά ενεργή την cloud-delivered protection (`MAPSReporting 2`, μέσω του cmdlet του Defender). Στέλνει μεταδεδομένα αρχείων και URL στη Microsoft για αρχεία που δεν κρίνονται τοπικά, και είναι το μόνο σημείο όπου το εργαλείο κρατά σκόπιμα ανοιχτή μια ροή δεδομένων: από αυτήν εξαρτώνται το block at first seen, το cloud block level και μερικοί ASR κανόνες, και η προδιαγραφή λέει ότι το Defender γίνεται μόνο πιο αυστηρό. Το **sample submission μένει όπως είναι** (η αυτόματη αποστολή δειγμάτων στέλνει αρχεία στη Microsoft): το `def-028` είναι `manual` και λέει στον χρήστη πώς να το αποφασίσει. Το `SubmitSamplesConsent` δεν γράφεται από κανένα entry: είναι στη never-touch λίστα και δεν υπάρχει στην allow-list των `defender_pref`.
- **Αλλαγή:** αν προτιμάς ιδιωτικότητα από ασφάλεια εδώ, σβήσε το `def-001` από το `manifests/m7-defender.json`: όσα εξαρτώνται από την cloud protection χάνουν το αποτέλεσμά τους. Το εργαλείο δεν το κάνει από μόνο του.

## D10. Αντιστοίχιση των ASR κανόνων σε profiles

- **Τι διάλεξα:** στο profile 2 μπαίνουν σε block οι τρεις κανόνες που η Microsoft ονομάζει «standard protection» (vulnerable drivers, κλοπή credentials από LSASS, WMI persistence) και τρεις κανόνες για email και Office που έχουν ελάχιστο ρίσκο: εκτελέσιμα από email, εκτελέσιμο περιεχόμενο του Office και μακροεντολές Win32. Στο profile 3 μπαίνουν σε block οι υπόλοιποι, με ρίσκο `medium`, και τρεις με `high`: μη έμπιστα USB, PsExec και WMI, και το κριτήριο prevalence και ηλικίας, που μπαίνει σε `warn` και όχι σε block.
- **Γιατί:** το ASR μπορεί να μπλοκάρει νόμιμα προγράμματα. Στο `warn` ο χρήστης μπορεί να παρακάμψει το μπλοκάρισμα (γενική γνώση, δεν επαληθεύτηκε σε VM).
- **Αλλαγή:** άλλαξε το `value` (`block`, `warn`) ή το `min_profile` του entry.

## D11. Audit: μόνο Success και Failure, ποτέ μείωση

- **Τι διάλεξα:** το εργαλείο γράφει μόνο την τιμή `success_failure` σε subcategories της Advanced Audit Policy και δεν χαμηλώνει υπάρχουσα πολιτική (ένα test το επιβάλλει). Το command line των διεργασιών καταγράφεται μόνο μαζί με το auditing δημιουργίας διεργασιών.
- **Γιατί:** το command line και το script block logging μπορούν να περιέχουν ευαίσθητο κείμενο (κωδικούς σε παραμέτρους). Για αυτό το `aud-003` έχει ρίσκο `medium` και το threat model το λέει.
- **Αλλαγή:** `-Exclude aud-*` στην εκτέλεση, ή σβήσε τα entries του `manifests/m9-audit.json`.

## D12. Το profile 1 μένει κλασικό και αβλαβές

- **Τι διάλεξα:** στο M5 και στο M6 το profile 1 έχει μόνο έλεγχους ανάγνωσης (Secure Boot, TPM 2.0, πιστοποιητικά Secure Boot, κρυπτογράφηση συστήματος, ενσωματωμένοι λογαριασμοί, firewall, driver blocklist, και ο χειροκίνητος έλεγχος ότι το test-signing είναι κλειστό) και δύο αλλαγές που κάνει κάθε οδηγός ασφαλείας: SMB1 off και WDigest off. Το profile 1 δεν πρέπει να σπάει τίποτα.
- **Αλλαγή:** μετακίνησε `min_profile`.

## D13. LSA protection με τιμή 2, ποτέ 1

- **Τι διάλεξα:** το `plt-008` γράφει `RunAsPPL=2`. Η Microsoft τεκμηριώνει την τιμή 1 ως ρύθμιση με μεταβλητή UEFI και την τιμή 2 ως ρύθμιση χωρίς αυτήν. Με το 1, το rollback της τιμής στο registry δεν είναι εγγυημένο ότι αναιρεί τη ρύθμιση, ενώ με το 2 αναιρείται με εγγραφή 0 ή διαγραφή της τιμής. Αν το σύστημα έχει ήδη 1, το plan το αλλάζει σε 2 και η μεταβλητή UEFI μένει· το `-Exclude plt-008*` κρατά το 1.
- **Κόστος:** Δεν ξέρω ποια plug-ins θα μπλοκαριστούν σε κάθε μηχάνημα. Το entry λέει στο notes να δεις πρώτα τα events 3033 και 3063 του CodeIntegrity.

## D14. Το `expected` και το `unverified` στο Home

- **Τι διάλεξα:** `expected` μπαίνει μόνο όταν ο μηχανισμός είναι ανεξάρτητος από την έκδοση: υπηρεσίες, scheduled tasks, AppX, optional features, τιμές που γράφει το ίδιο το Settings, ή τιμές που η Microsoft τεκμηριώνει για όλες τις εκδόσεις (π.χ. SMB signing) ή που γράφει το UI του adapter (NetBIOS). Κάθε policy key που η Microsoft τεκμηριώνει μόνο για Pro και πάνω είναι `unverified`, με τον όρο «αδρανές αν αγνοηθεί» και με οδηγίες επαλήθευσης σε VM.
- **Συνέπεια:** μόνο `expected` entries μπορούν να είναι `T0`.

## D15. Features με υπο-features: μερικό rollback

- **Τι διάλεξα:** το SMB1 και το PowerShell 2.0 είναι optional features με υπο-features. Το journal καταγράφει και ξαναενεργοποιεί μόνο το ίδιο το feature, όχι τα υπο-features που ήταν ενεργά πριν (π.χ. `SMB1Protocol-Client`). Γι' αυτό το rollback τους είναι `partial`, και το `limitation` λέει ότι αυτά ξαναενεργοποιούνται από το Windows Optional Features.

## D16. Τι δεν έβαλα στα manifests (με λόγο)

| Θέμα | Λόγος |
|---|---|
| WinRM off | Η Microsoft λέει να μην απενεργοποιείται, και δεν ακούει από προεπιλογή |
| FDResPub, fdPHost | Η Microsoft: «No guidance» |
| IPv6 `DisabledComponents` για τα tunnel bits | Η Microsoft το αποθαρρύνει, χαμηλή αξία |
| Delivery Optimization | Γειτνιάζει με την παράδοση updates (never-touch περιοχή) |
| Ενεργή διερεύνηση NCSI | Σπάει τα captive portals, αδύναμη τεκμηρίωση |
| Remote Assistance | Ισχνές πηγές |
| Credential Guard | Δεν ισχύει στο Home |
| Smart App Control | Η απενεργοποίηση είναι μονόδρομη: δεν το αγγίζω ποτέ |
| Αλλαγές στο BCD | Μόνο `manual` (`plt-006`): το εργαλείο δεν πειράζει boot configuration |
| Αλλαγές στα πιστοποιητικά Secure Boot | Never-touch: μόνο attest (`plt-003`) |

## D17. Το vulnerable driver blocklist: μόνο attest

- **Τι διάλεξα:** το `plt-009` διαβάζει την τιμή `VulnerableDriverBlocklistEnable` και αναφέρει αν είναι ενεργή (λείπουσα τιμή σημαίνει προεπιλογή, δηλαδή on). Η τιμή είναι στη never-touch λίστα («μένει on»), και ο validator απορρίπτει κάθε εγγραφή, ακόμη και με τιμή 1.
- **Γιατί:** μια πύλη που ξεχωρίζει «γράφω 1» από «γράφω 0» θα πρόσθετε κώδικα σε ένα κρίσιμο για την ασφάλεια σημείο. Η τιμή του registry τεκμηριώνεται μόνο από πηγή κοινότητας· η Microsoft λέει ότι το ίδιο το blocklist είναι προεπιλεγμένο από το 22H2.
- **Αλλαγή:** μετέτρεψέ το σε `enforce` και αφαίρεσε την τιμή από τη never-touch λίστα, αφού επαληθεύσεις σε VM ότι η τιμή ακολουθεί το toggle.

## D18. OneDrive: πώς, και γιατί η απεγκατάσταση είναι χειροκίνητη

- **Τι διάλεξα:** 1 entry στο profile 2 (`one-001`: μπλοκάρει την μετακίνηση Desktop, Documents και Pictures στο OneDrive) και 3 πίσω από `-OptIn no-onedrive`, profile 3: μπλοκ εκκίνησης (`DisableFileSyncNGSC`), μπλοκ του προσωπικού sync (`DisablePersonalSync`, ανά χρήστη) και χειροκίνητη απεγκατάσταση.
- **Γιατί η απεγκατάσταση δεν γίνεται από το εργαλείο:** δεν υπάρχει operation που τρέχει uninstaller τρίτου, και η σελίδα της Microsoft που διάβασα δίνει μόνο τα βήματα του Settings (δεν έψαξα για σιωπηλό διακόπτη απεγκατάστασης και δεν έχω τεκμηρίωση για κάποιον). Ένα τέτοιο operation θα ήταν η μεγαλύτερη μη δοκιμασμένη επιφάνεια του engine (εκτέλεση εξωτερικού αρχείου, έλεγχος υπογραφής και διαδρομής). Η προδιαγραφή ζητά «OneDrive removal as optional tier with explicit flag»: το flag υπάρχει, και ο αποκλεισμός δουλεύει όσο το πρόγραμμα είναι εγκατεστημένο. Η απεγκατάσταση γίνεται με τα βήματα του `one-004`, που πρώτα προστατεύουν τα αρχεία.
- **Αλλαγή:** αν θες αυτοματοποίηση, είναι στο `docs/BACKLOG.md` ως υποψήφιο operation.

## D19. Έλεγχος ισοδυναμίας των δύο linters

- **Τι διάλεξα:** ο έλεγχος των audit commands υπάρχει δύο φορές (Python στο CI, PowerShell στον engine). Τα κοινά vectors τρέχουν στο PowerShell μόνο με `selftest` στα Windows. Πρόσθεσα tests που διαβάζουν το `engine/Policy.ps1` και ελέγχουν ότι οι λίστες και τα regex είναι **ίδια** με του Python, και ότι ένα όνομα στο `ALLOWED_EXACT` δεν είναι ούτε απαγορευμένο ούτε ήδη επιτρεπτό από το ρήμα του.
- **Εξαίρεση ρήματος:** το `Confirm-SecureBootUEFI` επιτρέπεται κατ' όνομα (όχι το ρήμα `Confirm`): είναι το cmdlet που τεκμηριώνει η Microsoft για τον έλεγχο Secure Boot.

## D20. Η πρώτη εκτέλεση σε VM: τρία ψευδή λάθη του selftest

- **Τι έγινε:** στην πρώτη εκτέλεση σε VM Windows 11 Home με PowerShell 5.1 (σκόπιμα χωρίς RAM check, TPM 2.0 και Secure Boot, με `-AllowPlatformGaps`) η πύλη του `apply` βρήκε 3 αποτυχίες σε 504 ελέγχους και το `apply` σταμάτησε πριν αγγίξει το σύστημα. Το `selftest` και το `plan` είχαν τρέξει κανονικά. Και οι τρεις αποτυχίες ήταν λάθη του selftest ή του fake provider (το ένα με ρίζα σε βοηθητική συνάρτηση του engine), όχι του συστήματος και όχι της γλώσσας των Windows: ο έλεγχος «σύστημα που δεν είναι στα αγγλικά» προσομοιώνει ελληνικά Windows πάνω στο fake σύστημα.
- **Οι τρεις αιτίες:**
  1. «the state changed»: το `ConvertTo-WhCanonical` (`engine/Core.ps1`) διάβαζε `$Value.Keys`. Σε λεξικό που έχει εγγραφή με όνομα `keys` (όπως το snapshot του fake) το PowerShell επιστρέφει την εγγραφή αντί για τη λίστα των κλειδιών, και το snapshot έβγαινε πάντα ίδιο. Τώρα διαβάζει `$Value.psbase.Keys`, που ο οδηγός του PowerShell για τα hash tables τεκμηριώνει ως λύση.
  2. «only the folder that exists is listed»: ο fake provider επέστρεφε και φακέλους που δεν υπάρχουν, ενώ ο πραγματικός επιστρέφει μόνο όσους υπάρχουν. Διορθώθηκε ο fake.
  3. Ο έλεγχος μεταφρασμένου κειμένου έκανε `$facts['ui_language'] = 'el'` σε `[pscustomobject]`, που δεν δέχεται ευρετήριο («Unable to index into an object of type …PSObject»). Τώρα ορίζει την ιδιότητα.
- **Γιατί μετρά η πρώτη:** μέχρι τώρα οι έλεγχοι «ακριβώς όπως πριν» (rollback, wildcard registry, settings) συνέκριναν snapshots που ήταν πάντα ίδια, άρα δεν απέδειχναν τίποτα. Τώρα ένα test αποδεικνύει ότι το snapshot αλλάζει όταν αλλάζει το σύστημα, και αυτοί οι έλεγχοι δοκιμάζουν πραγματικά το rollback. Μπορεί να φέρουν στο φως πραγματικό πρόβλημα rollback που πριν δεν φαινόταν.
- **Θόρυβος:** τα «FAILED … (reverted)» και «Service … could not be stopped now» ήταν μηνύματα του engine για σφάλματα που το selftest προκαλεί σκόπιμα, για να δείξει ότι ένα αποτυχημένο βήμα ανατρέπεται. Έμοιαζαν με σφάλματα. Τώρα ο engine μένει σιωπηλός όσο τρέχουν τα cases.
- **Τι πρόσθεσα:** η έξοδος της πύλης γράφει `<test>: <έλεγχος>`, και ένα απρόσμενο σφάλμα γράφει αρχείο και γραμμή· κανόνας `STYLE` στο `tools/check_engine.py` για ανάθεση με ευρετήριο σε `[pscustomobject]` ή στα facts του fake, με δύο εγγραφές στα `FAULTS`· δύο tests Python (`psbase.Keys` στον canonicalizer, φίλτρο `dirs` στον fake).
- **Όριο:** δεν υπάρχει PowerShell εδώ, άρα οι διορθώσεις ελέγχθηκαν με ανάγνωση του κώδικα και με στατικούς ελέγχους, όχι με εκτέλεση. Το selftest δεν έχει ξανατρέξει μετά τη διόρθωση. Αν αποτύχει ξανά, η έξοδος λέει ποιο test και ποιος έλεγχος: κράτα όλη την έξοδο.
- **Αλλαγή:** αν μια αποτυχία της πύλης είναι ψευδής, διόρθωσε το test, όχι την πύλη. Το `-SkipSelfTest` είναι τελευταία λύση και μόνο σε VM με snapshot.

## D21. Τα audits που χρειάζονται module CIM ξανατρέχουν σε runspace FullLanguage

- **Τι έγινε:** στο πρώτο `apply -Profile 3` σε VM, το `verify` στο τέλος του έδωσε `ERROR` σε 29 entries: τα `tel-007` και `net-003`, και τα 27 του M7 (`def-001` έως `def-027`). Το μήνυμα ήταν «The 'Get-MpPreference' command was found in the module 'Defender', but the module could not be loaded» (το ίδιο για τα `Get-ScheduledTask`, `Get-NetFirewallProfile`, `Get-MpComputerStatus`). Έπεσε μόνο ο δεύτερος έλεγχος, το audit. Ο έλεγχος κατάστασης διαβάζει τα ίδια Defender preferences και tasks στο κύριο session και πέρασε: αλλιώς η αιτιολογία θα έγραφε και «is not in the desired state».
- **Αιτία:** τα audits τρέχουν σε runspace ConstrainedLanguage (D19). Τα Defender, ScheduledTasks και NetSecurity είναι modules CIM και δεν φορτώνουν εκεί, όταν ο περιορισμός μπαίνει από τον κώδικα και όχι από πολιτική του συστήματος. Η μόνη ένδειξη είναι το ίδιο το run: οι τρεις αυτές ομάδες εντολών αποτυγχάνουν στο ConstrainedLanguage runspace και δουλεύουν στο κύριο session, ενώ οι υπόλοιπες εντολές των audits (`Get-AppxPackage`, `Get-CimInstance`, `Get-WindowsOptionalFeature`, `Get-LocalUser`, `Confirm-SecureBootUEFI`, `Get-ItemProperty`) δεν έδωσαν αυτό το σφάλμα. Δεν βρήκα πηγή της Microsoft που να το λέει ρητά για τα CDXML modules: τεκμηριώνεται μόνο ότι οι περιορισμοί του ConstrainedLanguage εξαρτώνται από το αν υπάρχει πολιτική συστήματος.
- **Τι διάλεξα:** κάθε audit τρέχει πρώτα σε ConstrainedLanguage, όπως πριν. Αν δώσει `CommandNotFoundException` (η εντολή δεν φορτώθηκε), ξανατρέχει σε δεύτερο runspace FullLanguage. Και τα δύο ανοίγουν όταν χρειαστούν και κλείνουν στο `Stop-WhRealSession`. Η εντολή έχει περάσει το lint πριν φτάσει σε οποιοδήποτε από τα δύο.
- **Τι δεν διάλεξα:** (α) μόνιμα FullLanguage: χάνεται το δεύτερο φράγμα και για τα audits που δεν το χρειάζονται (registry, AppX, υπηρεσίες). (β) φόρτωση των modules πριν περιοριστεί το session: δεν ξέρω αν οι συναρτήσεις τους θα δούλευαν μετά, και δεν μπορώ να το δοκιμάσω εδώ. (γ) δικές μου συναρτήσεις αντί για τα 4 cmdlets: περισσότερος κώδικας χωρίς δυνατότητα δοκιμής.
- **Τι χάνεται:** στα audits που ξανατρέχουν σε FullLanguage το μόνο φράγμα είναι το lint (R10: μία γραμμή, μόνο single quotes, allow-list ρημάτων, χωρίς `&`, `::`, redirections, aliases, native exes). Το CI και ο engine το τρέχουν πριν από κάθε εντολή και ένα test κρατά τις δύο υλοποιήσεις ίδιες (D19). Το `docs/THREAT-MODEL.md` το γράφει.
- **Τα υπόλοιπα του ίδιου run** δείχνουν όρια της VM, όχι λάθη του engine: `plt-001` ERROR, γιατί το `Confirm-SecureBootUEFI` απαντά «Cmdlet not supported on this platform» (η VM δεν είναι UEFI με Secure Boot)· `plt-002`, `plt-003`, `plt-004` FAIL, γιατί δεν υπάρχει TPM 2.0, δεν έχει ξεκινήσει η ενημέρωση των πιστοποιητικών Secure Boot και δεν υπάρχει κρυπτογράφηση συσκευής· `plt-011` FAIL, γιατί η τιμή `Enabled=1` γράφτηκε (ο έλεγχος κατάστασης πέρασε) αλλά το memory integrity δεν τρέχει (θέλει επανεκκίνηση και virtualization).
- **Επιβεβαίωση (2026-11-23):** στο `verify -Profile 3` στη VM τα 29 entries δεν είναι πια ERROR. Δεν εμφανίζονται ούτε ως FAIL, και η ίδια λίστα δείχνει audits που έτρεξαν (`plt-002`, `plt-003`, `plt-004`, `plt-011`), άρα τα audits CIM έτρεξαν και ταίριαξαν με την αναμενόμενη τιμή. Η αιτία (modules CIM σε runspace ConstrainedLanguage) μένει συμπέρασμα και όχι τεκμηριωμένη από πηγή της Microsoft· το αποτέλεσμα όμως τη στηρίζει.
- **Όριο:** το test (`test_audit_runs_again_in_a_full_language_runspace_when_a_module_cannot_load`) κρατά μόνο το σχήμα του κώδικα. Την απόδειξη την έδωσε ένα run σε μία VM Windows 11 Home 25H2 (build 26200 ή νεότερο): σε άλλη έκδοση δεν έχει δοκιμαστεί.
- **Αλλαγή:** αν σε κάποια έκδοση τα modules δεν φορτώνουν ούτε σε FullLanguage, η επόμενη επιλογή είναι να διαβάζονται αυτές οι τιμές από τον provider (κύριο session) αντί για εντολή audit.

## D22. Το verify λέει πότε μια κλειστή πύλη είναι ο λόγος που ένα entry δεν εφαρμόστηκε

- **Τι έγινε:** μετά το `apply -Profile 3`, το `verify` έδωσε FAIL στα `appx-006` (Sticky Notes) και `appx-007` (To Do): «AppX Microsoft.MicrosoftStickyNotes is not in the desired state. Expected 0 but the command returned 1.» Και οι δύο έλεγχοι audit γύρισαν 1, δηλαδή η εφαρμογή είναι εγκατεστημένη και υπάρχει στην εικόνα (provisioned). Τα δύο entries έχουν `deletes_user_data` (D3): το `apply` τα παραλείπει εκτός αν δοθεί `-AcceptDataLoss`, και η αιτιολογία του FAIL δεν το έλεγε.
- **Τι κρατάω:** το `verify` συγκρίνει πάντα το σύστημα με το manifest, με τις πύλες ανοιχτές. Έτσι ένα entry που δεν εφαρμόστηκε δεν φαίνεται ποτέ «εντάξει», και μια εφαρμογή που ξαναήρθε με αναβάθμιση φαίνεται ως drift. Το status μένει `fail`.
- **Τι πρόσθεσα:** το `verify` και το drift task παίρνουν τις πύλες του τρέχοντος run (`Get-WhGates`). Αν ένα entry αποτύχει και η πύλη του είναι κλειστή, η αιτιολογία τελειώνει με «Apply skips this entry: <λόγος της πύλης>» (`Test-WhEntry`, `Invoke-WhVerify`, `Complete-WhRun`). Το test του selftest λέγεται `verify: a failing entry that a closed gate keeps apply away from says so`, και ένα test κειμένου στο `tests/test_engine_static.py` κρατά το σχήμα του κώδικα.
- **Τι απέρριψα:** (α) status `na` για entries με κλειστή πύλη: κρύβει την επιστροφή μιας εφαρμογής που αφαιρέθηκε με `-AcceptDataLoss`. (β) να διαβάζει το `verify` το journal και να ξεχωρίζει «το εφάρμοσε το εργαλείο» από «δεν εφαρμόστηκε ποτέ»: περισσότερος κώδικας σε σημείο που μόλις επαληθεύτηκε.
- **Όριο:** το `verify` θα βγάζει FAIL και exit code 1 όσο μένουν εγκατεστημένα entries που η πύλη κρατά κλειστά, και το drift task θα τα αναφέρει ως failing. Είναι σκόπιμο: έτσι δεν χάνεται ότι το σύστημα δεν συμφωνεί με το manifest. Για να φύγουν: `apply -Profile 3 -AcceptDataLoss -Only appx-006*,appx-007*` (σβήνει δεδομένα των εφαρμογών), ή `-Exclude appx-006*,appx-007*` στο `verify`. Δεν έχει τρέξει σε Windows: η αλλαγή ελέγχθηκε μόνο με στατικούς ελέγχους και το selftest που δεν έχει εκτελεστεί ακόμη.
- **Αλλαγή:** αν το FAIL από κλειστή πύλη μπερδεύει περισσότερο απ' όσο βοηθά, η επόμενη επιλογή είναι ξεχωριστό status στις αναφορές (όχι `na`) με δικό του μετρητή.
