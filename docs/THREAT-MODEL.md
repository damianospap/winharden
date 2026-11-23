# Threat model και modules

## 1. Πεδίο και παραδοχές

- Στόχος: Windows 11 **Home** 25H2 (26200.x) και 26H2 (26300.x), τοπικός διαχειριστής, Windows PowerShell 5.1 (64-bit). Ο preflight αρνείται builds παλαιότερα από 26200 (το 24H2 έχει λήξει για Home στις 13/10/2026), builds νεότερα από 26999 (εκτός αν δοθεί `-AllowUntestedBuild`) και εκδόσεις άλλες από Home (εκτός αν δοθεί `-AllowOtherEdition`).
- Το Home δεν έχει gpedit, Intune ή CSP. Οι policies γράφονται ως registry τιμές και μπορεί να αγνοούνται. Το εργαλείο δεν υποθέτει ότι ισχύουν: τα χαρακτηρίζει `unverified` μέχρι να παρατηρηθεί το αποτέλεσμα σε VM.
- Το εργαλείο **δεν χρησιμοποιεί δίκτυο**. Τα manifests είναι τοπικά αρχεία, και δεν υπάρχει `irm | iex` ή download-and-execute.
- Εκτός πεδίου: WDAC και App Control, outbound default-deny, ρύθμιση schannel και cipher suites, παρέμβαση σε ETW, LAPS, webhook, αποκλεισμός δικτύου, κρυπτογραφικές αλλαγές (μόνο audit). Βλ. `docs/DECISIONS.md` D4 και D16.
- **Ο engine έχει τρέξει μόνο σε μία VM Windows 11 Home, όχι σε πραγματικό μηχάνημα** (βλ. §4, πρώτη γραμμή).

## 2. Τι προστατεύουμε

| # | Αγαθό | Τι σημαίνει εδώ |
|---|---|---|
| A1 | Ιδιωτικότητα | Λιγότερη τηλεμετρία, διαφημιστικό προφίλ και καταγραφή οθόνης ή δραστηριότητας από AI |
| A2 | Καθαρότητα | Λιγότερες διαφημίσεις, προτάσεις, προεγκατεστημένες εφαρμογές και σκουπίδια |
| A3 | Ακεραιότητα και ενημερώσεις | Windows Update, servicing, Defender, TPM, Secure Boot και BitLocker συνεχίζουν να δουλεύουν |
| A4 | Αναστρεψιμότητα | Ό,τι αλλάζει μπορεί να επανέλθει, ή δηλώνεται ρητά ότι δεν μπορεί |
| A5 | Ασφάλεια του συστήματος | Μικρότερη επιφάνεια επίθεσης και καλύτερη ανίχνευση, χωρίς να χαλαρώνει καμία υπάρχουσα προστασία |

## 3. Απειλές που αντιμετωπίζει το εργαλείο

| Απειλή | Αντιμετώπιση | Όριο |
|---|---|---|
| Τηλεμετρία και feedback | M1: Required diagnostic data, feedback, tailored experiences, advertising ID, CEIP tasks, DiagTrack, WER, online speech | Στο Home δεν σβήνει το «Required diagnostic data»: το επίπεδο 0 ισχύει μόνο σε Enterprise, Education και Server |
| Διαφημίσεις και προτάσεις | M2: Start, lock screen, Settings, search, widgets | Η Microsoft αλλάζει συχνά τα Start και Settings: το `install-drift` εντοπίζει όσα επανέρχονται |
| Καταγραφή από AI | M3: Recall off και βεβαιωμένο, Copilot app, Click to Do, Paint AI, έλεγχοι για agentic features και Gaming Copilot | Η Microsoft δεν τεκμηριώνει registry τιμή ή εντολή που να δείχνει ότι το Recall αποθηκεύει snapshots: η βεβαίωση καλύπτει το component και τα policies, και το «Save snapshots» ελέγχεται χειροκίνητα |
| Bloat και junk | M4, M8 | Η αφαίρεση AppX αναιρείται μόνο μερικά (επανεγκατάσταση από το Store). Ο καθαρισμός δεν επαναφέρει αρχεία |
| Επιφάνεια επίθεσης του λειτουργικού | M6: SMB1, WDigest, LLMNR, NetBIOS, mDNS, SSDP, SMB signing, NTLM, Windows Script Host, PowerShell 2.0, αυτόματη εκτέλεση, προαιρετικά spooler και υπηρεσία Server | Policies που το Home μπορεί να αγνοεί είναι `unverified`. Μόνο ό,τι κλείνει χωρίς να σπάει βασικές λειτουργίες μπαίνει στο profile 2 |
| Κλοπή credentials και εκτέλεση κώδικα | M5: LSA protection, UAC, memory integrity, Kernel DMA. M7: ASR κανόνες, Network Protection, Controlled Folder Access, cloud protection | Memory integrity και Kernel DMA θέλουν υλικό και δεν επαληθεύονται σε VM. Το Credential Guard δεν υπάρχει στο Home |
| Πλατφόρμα και firmware | M5: έλεγχος (attest) Secure Boot, TPM 2.0, πιστοποιητικών Secure Boot 2023, κρυπτογράφησης συστήματος, ενσωματωμένων λογαριασμών, test-signing, driver blocklist | Μόνο ανάγνωση: οι ρυθμίσεις firmware, TPM και BitLocker είναι never-touch. Ένα «όχι» εμφανίζεται ως χάσμα με το χειροκίνητο βήμα |
| Ανίχνευση και ιχνηλασιμότητα | M9: Advanced Audit Policy και PowerShell script block logging | Τα logs δεν περιστρέφονται και δεν στέλνονται πουθενά από το εργαλείο (βλ. §4) |
| Συγχρονισμός προσωπικών αρχείων στο cloud | M10: μπλοκάρισμα μετακίνησης φακέλων (profile 2), opt-in αποκλεισμός του OneDrive και χειροκίνητη απεγκατάσταση | Η απεγκατάσταση είναι χειροκίνητη (`docs/DECISIONS.md` D18) |

## 4. Κίνδυνοι που δημιουργεί το ίδιο το εργαλείο

| Κίνδυνος | Αντίμετρο |
|---|---|
| **Ο engine έχει τρέξει μόνο σε μία VM Windows 11 Home** (`selftest`, `plan`, `apply`, `verify`, `rollback`· όχι πραγματικό μηχάνημα, και η έξοδος του `rollback` δεν έχει καταγραφεί). Μπορεί να έχει λάθη που κανένας έλεγχος εδώ δεν πιάνει (συμπεριφορά των cmdlets, 5.1 ιδιορρυθμίες, δικαιώματα) | Στατικός έλεγχος του κειμένου και tests στα κοινά vectors. Το `selftest` τρέχει πάνω στο fake σύστημα πριν από κάθε `apply`. Η εκτέλεση να γίνεται σε VM με snapshot (`docs/VERIFY-PROTOCOL.md`). Αν το selftest αποτύχει ψευδώς, το `apply` μπλοκάρεται: η πρώτη εκτέλεση σε VM έδειξε ακριβώς αυτό (`docs/DECISIONS.md` D20). Το `-SkipSelfTest` το παρακάμπτει, με δική σου ευθύνη |
| Σπάσιμο updates, Store ή Defender | Σκληρή never-touch λίστα (R07), ξανα-ελεγμένη από τον engine όταν φορτώνει τα manifests, servicing-adjacent μόνο με `-AllowServicingAdjacent` (R12), golden checks στο VERIFY-PROTOCOL |
| Αλλαγές που δεν αναιρούνται | Journal write-ahead: η προηγούμενη κατάσταση γράφεται πριν από κάθε αλλαγή. Δηλωμένο `reversibility` ανά entry, ρητό όριο για `partial` (R08). Κάθε entry είναι transaction: αποτυχία σημαίνει αυτόματη επαναφορά των ήδη αλλαγμένων |
| Απώλεια δεδομένων | Η επίπτωση γράφεται στο entry και το plan την εμφανίζει πριν την έγκριση. Entries που σβήνουν δεδομένα χρήστη (`deletes_user_data`) μπλοκάρονται εκτός αν δοθεί `-AcceptDataLoss` (D3). Ο καθαρισμός διαγράφει μόνο αρχεία παλαιότερα από μία ημέρα, σε allow-listed ρίζες, και δεν ακολουθεί junctions ή symbolic links |
| Ψευδής βεβαιότητα ότι «εφαρμόστηκε» | Το `home_effective` δεν γίνεται `verified` χωρίς παρατήρηση σε Home με build και ημερομηνία (R05). Κάθε αλλαγή διαβάζεται πίσω μετά την εγγραφή, και το `verify` τρέχει τα audits |
| Παραποίηση του journal | Κάθε εγγραφή έχει HMAC-SHA256 πάνω στο περιεχόμενό της και στο MAC της προηγούμενης: διαγραφή, αναδιάταξη ή αλλαγή γραμμής φαίνεται. Αν η επαλήθευση αποτύχει, ο engine δεν γράφει ούτε κάνει rollback (`-TrustJournal` το παρακάμπτει). **Όριο:** το κλειδί είναι δίπλα στο journal, σε φάκελο εγγράψιμο μόνο από SYSTEM και Administrators. Ένας διαχειριστής μπορεί να ξαναγράψει και τα δύο. Είναι tamper-evidence, όχι προστασία |
| Παραποίηση manifests (τα manifests είναι κώδικας) | Το plan δένεται στο hash των manifests και η έγκριση στο hash του plan. Ο engine εμφανίζει και γράφει στις αναφορές το fingerprint του κώδικα. **Όριο:** δεν υπάρχει υπογραφή ή εξωτερικό hash: όποιος μπορεί να γράψει στον φάκελο του εργαλείου πριν την εκτέλεση, ελέγχει τα πάντα. Το schema έχει `additionalProperties:false` |
| Έγχυση μέσω audit command | Lint (R10): μία γραμμή, μόνο single quotes, allow-list ρημάτων, απαγόρευση aliases, native exes, redirections, URLs. Το ίδιο lint τρέχει και στον engine, και ένα test απαιτεί οι δύο υλοποιήσεις να έχουν ίδιες λίστες και regex (D19). Ο engine τρέχει τα audits σε runspace ConstrainedLanguage. Μια εντολή που χρειάζεται module CIM (Defender, ScheduledTasks, NetSecurity), που δεν φορτώνει εκεί, ξανατρέχει σε runspace FullLanguage, και μόνο αφού έχει περάσει το lint (D21): σε εκείνα τα audits το lint είναι το μόνο φράγμα |
| Το drift task ως δρόμος ανύψωσης δικαιωμάτων | Ένα task SYSTEM που τρέχει scripts είναι κίνδυνος αν ένας απλός χρήστης μπορεί να τα αλλάξει. Τα αρχεία αντιγράφονται σε φάκελο του Program Files που γράφουν μόνο SYSTEM, Administrators και TrustedInstaller, και το ACL ελέγχεται πριν καταχωρηθεί το task. Το task μόνο επαληθεύει· το `-Reapply` είναι ρητή επιλογή και ποτέ δεν περιλαμβάνει entries που σβήνουν δεδομένα ή αγγίζουν το servicing |
| Cleanup: διαγραφή «αλλού» μέσω link | Η απαρίθμηση δεν μπαίνει σε junction ή symbolic link και δεν τα δίνει ως αρχεία. **Όριο:** ο έλεγχος γίνεται κατά την απαρίθμηση, όχι ατομικά με τη διαγραφή· σε φακέλους temp, όπου οι απλοί χρήστες ήδη γράφουν, υπάρχει θεωρητικό παράθυρο ανάμεσα στα δύο (TOCTOU) |
| Ευαίσθητο κείμενο στα logs που ενεργοποιεί το M9 | Το command line των διεργασιών (`aud-003`) και το script block logging (`aud-006`) μπορούν να περιέχουν κωδικούς ή κλειδιά που δόθηκαν ως παράμετροι. Το `aud-003` έχει ρίσκο `medium`. Τα logs μένουν τοπικά και δεν περιστρέφονται από το εργαλείο: μέγεθος και πρόσβαση είναι δική σου ευθύνη |
| Defender: ροή δεδομένων προς τη Microsoft | Το `def-001` κρατά ανοιχτή την cloud protection (σκόπιμα, D9). Το sample submission δεν αλλάζει και μένει επιλογή του χρήστη (`def-028`) |
| Per-user τιμές μόνο στον τρέχοντα χρήστη | Το `scope: user` εφαρμόζεται σε κάθε υπάρχον profile και στο Default user hive. Αν το εργαλείο τρέχει ως SYSTEM, οι audits που διαβάζουν HKCU παραλείπονται (PF09) και ο έλεγχος κατάστασης καλύπτει κάθε profile |
| Σκληροκωδικοποιημένες διαδρομές | Ο engine λύνει φακέλους από το περιβάλλον (μεταβλητές συστήματος και χρήστη) και αρνείται ρίζα που δεν ξεκινά από γνωστή μεταβλητή |
| Δύο εκτελέσεις ταυτόχρονα | Mutex ανά μηχάνημα: μία εκτέλεση τη φορά |
| Μη διαβασμένο ή μη επαληθευμένο entry | Κάθε entry έχει αιτιολόγηση, επίπτωση, audit, rollback και πηγές (R10, schema). Τα `unverified` λένε πώς θα επαληθευτούν (test) |

## 5. Υπολειπόμενο ρίσκο

- Η Microsoft μπορεί να αλλάξει ή να αγνοήσει ρυθμίσεις χωρίς ειδοποίηση. Δεν μπορούμε να το αποκλείσουμε, μόνο να το εντοπίζουμε (`install-drift`).
- Δεδομένα που φεύγουν από τη συσκευή με τη λειτουργία των Windows ή των λογαριασμών (cloud side) δεν ελέγχονται από ρυθμίσεις της συσκευής.
- Δεν πειράζουμε το ETW, το firewall ή το δίκτυο, άρα η πρόσβαση της τηλεμετρίας σε επίπεδο δικτύου δεν αποκλείεται.
- 43 από τα 133 entries στηρίζονται σε policy keys που το Home μπορεί να αγνοεί: μέχρι να επαληθευτούν σε VM, μπορεί να μην κάνουν τίποτα. Το `verify` θα δείξει την τιμή στο registry, όχι ότι η Microsoft την τηρεί.
- Secure Boot: τα πιστοποιητικά 2011 λήγουν μέσα στο 2026 (KEK CA 24/6, UEFI CA 27/6, Windows Production PCA 19/10). Δεν αγγίζουμε τίποτα σχετικό, ούτε το task `\Microsoft\Windows\PI\Secure-Boot-Update`. Το `plt-003` μόνο αναφέρει αν τα νέα πιστοποιητικά του 2023 έχουν εγκατασταθεί.
- Ένα κακόβουλο πρόγραμμα με δικαιώματα διαχειριστή μπορεί να αναιρέσει τα πάντα, να αλλάξει το journal και να παραποιήσει τις αναφορές. Το εργαλείο μειώνει την επιφάνεια και βοηθά να φανούν αλλαγές, δεν αντικαθιστά την προστασία από το να μην τρέχει κάτι ως διαχειριστής.

## 6. Modules

| Module | Περιεχόμενο | Entries | Κατάσταση |
|---|---|---|---|
| Engine | Preflight, plan, journal, apply, verify, rollback, αναφορές, drift task, selftest | | Γραμμένος, **έχει τρέξει μόνο σε μία VM Windows 11 Home** (selftest, plan, apply, verify, rollback· όχι πραγματικό μηχάνημα) |
| M1 telemetry | Διαγνωστικά, feedback, advertising ID, CEIP, DiagTrack, WER, online speech | 11 | Manifest, tests |
| M2 consumer | Διαφημίσεις και προτάσεις | 11 | Manifest, tests |
| M3 AI | Recall, Copilot, Click to Do, Paint AI, agentic, Gaming Copilot | 9 | Manifest, tests |
| M4 AppX | Προεγκατεστημένες εφαρμογές | 30 | Manifest, tests |
| M5 platform | Έλεγχοι πλατφόρμας, UAC, LSA, memory integrity, Kernel DMA | 12 | Manifest, tests |
| M6 network | Παλιά πρωτόκολλα και υπηρεσίες δικτύου | 18 | Manifest, tests |
| M7 Defender | Hardening, όχι η μηχανή | 28 | Manifest, tests |
| M8 cleanup | Σκουπίδια και logs | 4 | Manifest, tests |
| M9 audit | Πολιτική καταγραφής ασφάλειας | 6 | Manifest, tests |
| M10 OneDrive | Μπλοκάρισμα και απεγκατάσταση (opt-in) | 4 | Manifest, tests |

«Manifest, tests» σημαίνει ότι τα entries περνούν validator και tests. Δεν σημαίνει ότι δοκιμάστηκαν σε Windows.
