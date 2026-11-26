# winharden

Debloat και hardening για **Windows 11 Home**: plan πριν από κάθε αλλαγή, αναίρεση από journal, επαλήθευση με ανεξάρτητους ελέγχους.

Κάθε ρύθμιση είναι ένα entry σε manifest JSON, με αιτιολόγηση, επίπτωση για τον χρήστη, εντολή ελέγχου, τρόπο αναίρεσης και πηγές με βαθμό αξιοπιστίας. Ο engine διαβάζει τα manifests, δείχνει τι θα αλλάξει, ζητά έγκριση, καταγράφει κάθε αλλαγή πριν την κάνει και ελέγχει το αποτέλεσμα. Δεν χρησιμοποιεί δίκτυο και δεν κατεβάζει τίποτα: δεν υπάρχει `irm | iex`.

| | |
|---|---|
| Πλατφόρμα | Windows 11 Home 25H2 (build 26200) έως build 26999 |
| Runtime | Windows PowerShell 5.1, 64-bit, ως Administrator. Καμία εξάρτηση |
| Περιεχόμενο | 133 entries σε 10 modules, 3 profiles και 5 entries που μπαίνουν μόνο με `-OptIn` |
| Έκδοση | 0.1.0 |
| Κατάσταση | **Πρώιμη.** Έχει τρέξει σε μία VM, όχι ακόμη σε πραγματικό μηχάνημα |

> Διάβασε την ενότητα [Κατάσταση](#κατάσταση) πριν το τρέξεις, και δοκίμασέ το πρώτα σε VM με snapshot.

## Περιεχόμενα

- [Κατάσταση](#κατάσταση)
- [Αρχές και όρια](#αρχές-και-όρια)
- [Απαιτήσεις](#απαιτήσεις)
- [Γρήγορη εκκίνηση](#γρήγορη-εκκίνηση)
- [Profiles και modules](#profiles-και-modules)
- [Εντολές και επιλογές](#εντολές-και-επιλογές)
- [Μοντέλο ασφαλείας](#μοντέλο-ασφαλείας)
- [Επαλήθευση και αναφορές](#επαλήθευση-και-αναφορές)
- [Αρχεία που γράφει το εργαλείο](#αρχεία-που-γράφει-το-εργαλείο)
- [Παρακολούθηση drift](#παρακολούθηση-drift)
- [Manifests](#manifests)
- [Αρχιτεκτονική](#αρχιτεκτονική)
- [Ανάπτυξη και έλεγχοι](#ανάπτυξη-και-έλεγχοι)
- [Αντιμετώπιση προβλημάτων](#αντιμετώπιση-προβλημάτων)
- [Ασφάλεια και αναφορά προβλημάτων](#ασφάλεια-και-αναφορά-προβλημάτων)
- [Έγγραφα](#έγγραφα)
- [Άδεια και ευθύνη](#άδεια-και-ευθύνη)

## Κατάσταση

Πρώιμη έκδοση. Ο πίνακας λέει τι έχει αποδειχθεί και τι όχι.

| Θέμα | Σήμερα |
|---|---|
| Πού έχει τρέξει | Σε **μία** VM Windows 11 Home με PowerShell 5.1. Όχι ακόμη σε πραγματικό μηχάνημα |
| Τι έτρεξε | `selftest`, `plan`, `apply -Profile 3`, `verify -Profile 3` και το `rollback` του πρώτου apply. Ο δοκιμαστής ανέφερε ότι το rollback ήταν σωστό· η έξοδός του δεν έχει καταγραφεί |
| Τι βρήκε η VM | Τρία ψευδή λάθη του `selftest` (D20) και `ERROR` σε 29 entries, επειδή το audit τους δεν μπορούσε να τρέξει (D21). Διορθώθηκαν και επιβεβαιώθηκαν στη VM. Η αλλαγή D22 (το `verify` εξηγεί γιατί ένα entry δεν εφαρμόστηκε) δεν έχει ακόμη τρέξει σε Windows |
| Entries που πέρασαν το πρωτόκολλο επαλήθευσης | **0 από 133.** Τα 90 είναι `expected` και τα 43 `unverified`: policies που το Home μπορεί να αγνοεί |
| Δεν έχει δοκιμαστεί | Το drift task (`install-drift`) και πραγματικό υλικό: TPM, Secure Boot, BitLocker, memory integrity |
| Ανεξάρτητη αναθεώρηση | Δεν έχει γίνει |
| Ανοιχτά σημεία | `docs/BACKLOG.md`, μαζί με τις εξαιρέσεις (ownership) του πρώτου `apply` που ανέφερε ο δοκιμαστής και δεν έχουν ακόμη καταγραφεί |
| Αυτόματοι έλεγχοι | Εκατοντάδες tests σε Python πάνω στα manifests, στα κοινά vectors των δύο linters και στον κώδικα PowerShell ως κείμενο. Το PowerShell δεν εκτελείται στο περιβάλλον ανάπτυξης, οπότε αυτοί οι έλεγχοι δεν αποδεικνύουν τη συμπεριφορά στα Windows |

> **Πριν από οποιοδήποτε `apply`:** φτιάξε VM Windows 11 Home με snapshot και ακολούθησε το [`docs/VERIFY-PROTOCOL.md`](docs/VERIFY-PROTOCOL.md). Το profile 3 μπορεί να σπάσει παλιά προγράμματα και drivers. Μην το τρέξεις πρώτα στο μηχάνημα που χρησιμοποιείς.

## Αρχές και όρια

| Αρχή | Πώς υλοποιείται |
|---|---|
| Plan πριν από αλλαγή | Το `plan` διαβάζει το σύστημα και δείχνει «πριν → μετά» για κάθε στόχο. Το `apply` ζητά έγκριση που δένεται στο hash του plan |
| Καταγραφή πριν από εγγραφή | Κάθε στόχος γράφεται πρώτα στο journal (αλυσίδα HMAC-SHA256) και μετά αλλάζει. Κάθε αλλαγή διαβάζεται πίσω |
| Transaction ανά entry | Αν αποτύχει ένα βήμα, επανέρχονται οι στόχοι του ίδιου entry που είχαν αλλάξει, πριν ξεκινήσει το επόμενο entry |
| Αναίρεση με δηλωμένα όρια | Το `rollback` επαναφέρει από το journal. Ό,τι δεν επανέρχεται (αφαιρεμένες εφαρμογές, διαγραμμένα αρχεία) δηλώνεται `partial` στο entry και στο plan, πριν την αλλαγή |
| Ανεξάρτητη επαλήθευση | Το `verify` ελέγχει δύο φορές: ο engine διαβάζει τους στόχους, και τρέχουν οι read-only εντολές ελέγχου του manifest |
| Ειλικρίνεια για το Home | Policy που η Microsoft τεκμηριώνει μόνο για Pro και πάνω σημειώνεται `unverified`, με οδηγία επαλήθευσης σε VM. Κανένα entry δεν γίνεται `verified` χωρίς παρατήρηση σε Home, με build και ημερομηνία (R05) |
| Λίστα που δεν αγγίζεται | `policy/never-touch.json`: Windows Update, Store, μηχανή του Defender, Secure Boot, TPM, BitLocker. Την ελέγχει ο validator και την ξανα-ελέγχει ο engine όταν φορτώνει τα manifests |
| Χωρίς δίκτυο | Ο engine δεν έχει καμία κλήση δικτύου, και οι εντολές ελέγχου των manifests απορρίπτονται από τον lint αν έχουν |
| Idempotent | Δεύτερο `apply` σε σύστημα που ήδη συμφωνεί: «Nothing to change», κανένα checkpoint |

Όρια, δηλαδή τι το εργαλείο **δεν** κάνει:

- Δεν σβήνει τα διαγνωστικά δεδομένα. Το Home δεν επιτρέπει επίπεδο 0: το εργαλείο κρατά το Required (`tel-001`).
- Δεν απενεργοποιεί ποτέ Windows Update, SmartScreen, firewall ή Defender. Για τον Defender κάνει μόνο hardening.
- Δεν αλλάζει Secure Boot, TPM και BitLocker: τα ελέγχει μόνο (`attest`).
- Δεν απεγκαθιστά το OneDrive: μπλοκάρει την εκκίνηση και τη σύνδεση με προσωπικό λογαριασμό (opt-in) και δίνει χειροκίνητα βήματα για την απεγκατάσταση (D18).
- Δεν υποστηρίζει άλλη έκδοση από Home, ούτε build πριν από το 25H2.
- Είναι τοπικό εργαλείο για ένα μηχάνημα: δεν έχει κεντρική διαχείριση και δεν στέλνει αναφορές πουθενά.
- Η εξαγωγή XCCDF είναι μορφή αποτελεσμάτων: δεν είναι πιστοποίηση συμμόρφωσης με benchmark και δεν έχει επικυρωθεί με εργαλεία του NIST.
- Εκτός πεδίου είναι επίσης WDAC και App Control, outbound default-deny, ρύθμιση schannel, ETW και LAPS (`docs/THREAT-MODEL.md`, §1).

## Απαιτήσεις

| | |
|---|---|
| Λειτουργικό | Windows 11 **Home**, build 26200 έως 26999 |
| Shell | Μόνο Windows PowerShell 5.1 (`powershell.exe`), 64-bit |
| Δικαιώματα | Administrator |
| Πλατφόρμα | Secure Boot ενεργό και TPM 2.0 ενεργό. Χωρίς αυτά το `apply` σταματά, εκτός αν δοθεί `-AllowPlatformGaps` |
| Κατάσταση συστήματος | Καμία εκκρεμής επανεκκίνηση |
| Δίκτυο | Δεν χρειάζεται |

Ο έλεγχος preflight καλύπτει, πριν από την αλλαγή, τα δικαιώματα, το 64-bit, την έκδοση και το build των Windows, την εκκρεμή επανεκκίνηση, το Secure Boot και το TPM, με κωδικό και διάγνωση (πίνακας στο [Μοντέλο ασφαλείας](#μοντέλο-ασφαλείας)). Δεν ελέγχει την έκδοση του PowerShell: ξεκίνα το εργαλείο πάντα με το `powershell.exe`.

## Γρήγορη εκκίνηση

Σε VM Windows 11 Home με snapshot. Άνοιξε το Windows PowerShell με «Run as administrator», πήγαινε στον φάκελο του έργου και τρέξε:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 selftest
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 plan -Profile 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 apply -Profile 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 verify -Profile 1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 checkpoints
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1 rollback -To latest
```

Το `-ExecutionPolicy Bypass` ισχύει μόνο για αυτή τη διεργασία και δεν αλλάζει την πολιτική του συστήματος.

1. **`selftest`** τρέχει τα tests του engine πάνω σε σύστημα στη μνήμη. Δεν αλλάζει τίποτα. Το `apply` το ξανατρέχει πριν αλλάξει οτιδήποτε και αρνείται να συνεχίσει αν αποτύχει.
2. **`plan`** διαβάζει το σύστημα και δείχνει τι θα αλλάξει και γιατί. Δεν αλλάζει τίποτα. Σώζει το plan και τυπώνει την εντολή που εφαρμόζει ακριβώς αυτό.
3. **`apply`** δείχνει το plan και ζητά να γράψεις `APPLY`. Μετά δημιουργεί σημείο επαναφοράς (best effort) και checkpoint, εφαρμόζει entry προς entry, τρέχει `verify` και γράφει τις αναφορές. Αν χρειάζεται επανεκκίνηση, το λέει στο τέλος. Μη διαδραστικά: `apply -Profile 1 -Yes -PlanId <id>`.
4. **`verify`** συγκρίνει το σύστημα με τα manifests ([Επαλήθευση και αναφορές](#επαλήθευση-και-αναφορές)). Δώσε το ίδιο `-Profile` με το `apply`.
5. **`checkpoints`** επαληθεύει το journal και τυπώνει τα checkpoints. Το **`rollback -To latest`** αναιρεί τις αλλαγές του τελευταίου `apply` και ζητά να γράψεις `ROLLBACK`.

Το plan έχει αυτή τη μορφή (τα `<…>` είναι τιμές που συμπληρώνει ο engine):

```text
Plan <id>  profile <N>  engine <έκδοση>
  to change: <n> entries (<m> targets)   already compliant: <n>   not applicable: <n>   blocked: <n>

[CHANGE] <entry id>  (profile <p>, risk <low|medium|high>, Home effect: <home_effective>)
    <τίτλος>
    <στόχος>:  <πριν>  ->  <μετά>
    needs a restart to take effect
[BLOCKED] <entry id>  (profile <p>, risk <…>, Home effect: <…>)
    <τίτλος>
    <ο λόγος>
```

| Κατάσταση στο plan | Σημασία |
|---|---|
| `CHANGE` | Θα αλλάξει. Εμφανίζεται κάθε στόχος με την τιμή πριν και μετά |
| `SKIP` | Δεν ισχύει εδώ: λείπει η υπηρεσία, το task, το feature ή ο φάκελος, ή δεν ταιριάζει το build ή η έκδοση |
| `BLOCKED` | Δεν θα αλλάξει: κλειστή πύλη, υλικό που λείπει, ή κάτι που ο engine δεν μπορεί να αλλάξει με ασφάλεια (π.χ. τιμή με τύπο που δεν αποθηκεύεται, κατάσταση που δεν διαβάζεται) |

Τα entries που συμφωνούν ήδη μετρώνται («already compliant») αλλά δεν εμφανίζονται. Στο τέλος το plan αναφέρει όσα δεν επιλέχθηκαν και θέλουν `-OptIn`, όσα ελέγχονται μόνο (`attest`) και όσα είναι χειροκίνητα.

## Profiles και modules

Κάθε profile περιέχει τα χαμηλότερα: το profile N παίρνει κάθε entry με `min_profile` έως N. Το ρίσκο ανεβάζει το ελάχιστο profile: `medium` από το 2, `high` μόνο στο 3 (R16).

| Profile | Όνομα | Νέα | Σύνολο | Τι περιέχει |
|---|---|---|---|---|
| 1 | Classic | 36 | 36 | Ό,τι θα έκανε ένα εργαλείο τύπου WinUtil: τηλεμετρία, διαφημίσεις, βασικό bloat, προσωρινά αρχεία, SMB1 και WDigest off, και έλεγχοι ανάγνωσης για την πλατφόρμα. Στόχος: να μη σπάει τίποτα |
| 2 | Private | 46 | 82 | Ιδιωτικότητα και επιφάνεια επίθεσης: Defender hardening, παλιά πρωτόκολλα, LSA protection, UAC, περισσότερες εφαρμογές |
| 3 | Deep | 46 | 128 | Βαθιές αλλαγές: οι περισσότεροι ASR κανόνες, Controlled Folder Access, audit, memory integrity, Kernel DMA, πλήρης αφαίρεση εφαρμογών. Μπορεί να σπάσει παλιά προγράμματα και drivers |

Πέντε entries είναι εκτός κάθε profile και μπαίνουν μόνο με `-OptIn <όνομα>`:

| `-OptIn` | Entries | Τι κάνει |
|---|---|---|
| `no-printing` | 1 | Απενεργοποιεί την υπηρεσία Print Spooler (`net-017`): κανένας εκτυπωτής, ούτε εικονικός όπως το Microsoft Print to PDF |
| `no-file-sharing` | 1 | Απενεργοποιεί την υπηρεσία Server (`net-018`): κανένα άλλο μηχάνημα δεν συνδέεται σε κοινόχρηστους φακέλους ή εκτυπωτές αυτού |
| `no-onedrive` | 3 | Εμποδίζει την εκκίνηση του OneDrive (`one-002`) και τη σύνδεση με προσωπικό λογαριασμό Microsoft (`one-003`). Το `one-004` είναι χειροκίνητο: βήματα απεγκατάστασης, ο engine δεν αλλάζει τίποτα |

| Module | Prefix | Περιεχόμενο | Entries |
|---|---|---|---|
| M1 telemetry | `tel` | Διαγνωστικά, feedback, advertising ID, CEIP, DiagTrack, Error Reporting, online speech | 11 |
| M2 consumer | `ads` | Διαφημίσεις και προτάσεις σε Start, lock screen, Settings, search, widgets | 11 |
| M3 AI | `ai` | Recall (απενεργοποιημένο και βεβαιωμένο σε κάθε profile), Copilot, Click to Do, Paint AI | 9 |
| M4 AppX | `appx` | Αφαίρεση προεγκατεστημένων εφαρμογών (ονόματα ακριβή, ζεύγος provisioned και `-AllUsers`) | 30 |
| M5 platform | `plt` | Secure Boot, TPM 2.0, κρυπτογράφηση συστήματος (έλεγχοι), UAC, LSA protection, memory integrity, Kernel DMA | 12 |
| M6 network | `net` | SMB1, WDigest, LLMNR, NetBIOS, SMB signing, NTLM, mDNS, SSDP, Script Host, spooler | 18 |
| M7 Defender | `def` | Μόνο hardening: cloud protection, ASR κανόνες, Network Protection, Controlled Folder Access | 28 |
| M8 cleanup | `cln` | Προσωρινά αρχεία και σκουπίδια (μόνο διαδρομές με πηγή, μόνο αρχεία παλαιότερα από μία ημέρα) | 4 |
| M9 audit | `aud` | Advanced Audit Policy και PowerShell script block logging | 6 |
| M10 OneDrive | `one` | Μπλοκάρισμα μετακίνησης φακέλων στο OneDrive, opt-in αποκλεισμός και χειροκίνητη απεγκατάσταση | 4 |

Το prefix ταιριάζει με `-Only` και `-Exclude` (`-Only 'tel-*'`). Η πλήρης λίστα είναι στο [`docs/REFERENCE.md`](docs/REFERENCE.md) (παράγεται από τα manifests, με profile, ρίσκο και κανάλι ανά entry) και στην εντολή `list -Profile 3`.

## Εντολές και επιλογές

Στα παραδείγματα το `<ps>` σημαίνει `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\winharden.ps1`.

| Εντολή | Τι κάνει | Αλλάζει ρυθμίσεις |
|---|---|---|
| `help` | Εμφανίζει τη βοήθεια | Όχι |
| `list` | Λίστα entries με id, profile, tier, mode, ρίσκο και `home_effective` (`-Profile` και `-Only` φιλτράρουν) | Όχι |
| `plan` | Δείχνει τι θα αλλάξει και γιατί, και σώζει το plan | Όχι |
| `apply` | Plan, έγκριση, εφαρμογή, `verify`, αναφορές | **Ναι** |
| `verify` | Ελέγχει το σύστημα με τα manifests και γράφει αναφορές | Όχι |
| `rollback` | Επαναφέρει ό,τι άλλαξε μετά από ένα checkpoint | **Ναι** |
| `checkpoints` | Επαληθεύει το journal και τυπώνει τα checkpoints | Όχι |
| `status` | Δείχνει στοιχεία πλατφόρμας, preflight, journal και drift task | Όχι |
| `selftest` | Τρέχει τα tests του engine πάνω σε σύστημα στη μνήμη | Όχι |
| `install-drift` | Εγκαθιστά το drift task και ένα προστατευμένο αντίγραφο του εργαλείου | **Ναι** |
| `remove-drift` | Αφαιρεί το drift task (και με `-RemoveFiles` το αντίγραφο) | **Ναι** |
| `drift` | Η εντολή που τρέχει το drift task: `verify` και αναφορά. Με `-Reapply` ξαναεφαρμόζει | Μόνο με `-Reapply` |

Οι εντολές που δεν αλλάζουν ρυθμίσεις μπορεί να γράψουν στον φάκελο κατάστασης (log, plans, αναφορές): δες [Αρχεία που γράφει το εργαλείο](#αρχεία-που-γράφει-το-εργαλείο).

| Επιλογή | Ισχύει για | Τι κάνει |
|---|---|---|
| `-Profile N` | `list`, `plan`, `apply`, `verify`, `drift`, `install-drift` | Επιλέγει profile 1, 2 ή 3 (προεπιλογή 1). Κάθε profile περιέχει τα χαμηλότερα |
| `-Only <μοτίβο>` | `list`, `plan`, `apply`, `verify`, `drift` | Μόνο entries με id που ταιριάζει (wildcards: `tel-*`). Το `install-drift` δεν το περνά στο task |
| `-Exclude <μοτίβα>` | `plan`, `apply`, `verify`, `drift`, `install-drift` | Αφήνει έξω entries. Λίστα με κόμμα: `'appx-*,def-020*'` |
| `-OptIn <όνομα>` | `plan`, `apply`, `verify`, `drift`, `install-drift` | Περιλαμβάνει entries που θέλουν ρητή επιλογή (`no-printing`, `no-file-sharing`, `no-onedrive`) |
| `-PlanId <id>` | `apply` | Το id του plan που έλεγξες, όπως το έδειξε το `plan` ή το `apply` |
| `-Yes` | `apply`, `rollback` | `apply`: έγκριση χωρίς ερώτηση, μόνο μαζί με το σωστό `-PlanId`. `rollback`: παραλείπει την ερώτηση `ROLLBACK` |
| `-To <checkpoint>` | `rollback` | Το checkpoint (δες `checkpoints`) ή `latest` για το πιο πρόσφατο |
| `-AcceptDataLoss` | `plan`, `apply`, `verify`, `drift` | Ανοίγει την πύλη για entries που σβήνουν δεδομένα χρήστη που κανένα rollback δεν επαναφέρει. Το `verify` τη χρησιμοποιεί μόνο για να πει ποιες πύλες είναι κλειστές. Το `install-drift` δεν την περνά ποτέ στο task |
| `-AllowServicingAdjacent` | `plan`, `apply`, `verify`, `drift`, `install-drift` | Ανοίγει την πύλη για entries που αγγίζουν στοιχεία κοντά στο servicing των Windows. Το `install-drift` την περνά και στο task |
| `-AllowPlatformGaps` | όλες τις εντολές που ελέγχουν preflight | Συνεχίζει χωρίς Secure Boot ή TPM 2.0. Entries που τα χρειάζονται μένουν blocked |
| `-AllowUntestedBuild` | όμοια | Το build νεότερο από 26999 γίνεται προειδοποίηση αντί για blocker |
| `-AllowOtherEdition` | όμοια | Η έκδοση που δεν είναι Home γίνεται προειδοποίηση. Οι σημειώσεις Home των manifests δεν την περιγράφουν |
| `-IgnorePendingReboot` | όμοια | Η εκκρεμής επανεκκίνηση γίνεται προειδοποίηση |
| `-NoRestorePoint` | `apply` | Δεν δημιουργεί σημείο επαναφοράς συστήματος |
| `-SkipSelfTest` | `apply`, `drift`, `install-drift` | Παραλείπει το `selftest`. Δεν συνιστάται |
| `-TrustJournal` | `apply`, `rollback`, `drift` | Συνεχίζει ενώ η επαλήθευση του journal απέτυχε. Μόνο αν είσαι βέβαιος ότι κανείς δεν το άλλαξε |
| `-Quick` | `verify` | Μόνο έλεγχος κατάστασης, χωρίς εντολές audit |
| `-OutDir <φάκελος>` | `apply`, `verify`, `drift` | Γράφει τις αναφορές εκεί αντί για το `reports\<run>` |
| `-Reapply` | `install-drift`, `drift` | Ξαναεφαρμόζει όσα ξέφυγαν (στο `install-drift`: το task). Το task δεν παίρνει ποτέ `-AcceptDataLoss`, άρα δεν αγγίζει entries που σβήνουν δεδομένα |
| `-RemoveFiles` | `remove-drift` | Σβήνει και το εγκατεστημένο αντίγραφο |

Παραδείγματα:

```powershell
<ps> list -Profile 3                               # τι περιέχει το profile 3
<ps> plan -Profile 2 -Exclude 'appx-*'             # profile 2 χωρίς αφαίρεση εφαρμογών
<ps> plan -Profile 1 -OptIn no-printing            # profile 1 και απενεργοποίηση του spooler
<ps> apply -Profile 2 -Yes -PlanId <id>            # εφαρμόζει ακριβώς το plan που έλεγξες
<ps> verify -Profile 3 -OutDir C:\winharden-reports
<ps> rollback -To cp-<run>                         # επιστροφή σε συγκεκριμένο checkpoint
```

| Κωδικός εξόδου | Σημασία |
|---|---|
| 0 | Ολοκληρώθηκε χωρίς αποτυχίες |
| 1 | Ολοκληρώθηκε με αποτυχίες: entry που επανήλθε, `fail` ή `error` στο `verify`, αποτυχία του rollback ή του `selftest` |
| 2 | Αρνήθηκε να ξεκινήσει: preflight, λάθος χρήση (π.χ. `rollback` χωρίς `-To`) ή δεν δόθηκε έγκριση |
| 3 | Σφάλμα ακεραιότητας ή εσωτερικό σφάλμα: αποτυχία του `selftest` πριν από το `apply`, journal που δεν επαληθεύεται, manifests που απορρίφθηκαν |

## Μοντέλο ασφαλείας

Οι προστασίες είναι στρώματα: κάθε ένα καλύπτει ό,τι θα ξέφευγε από το προηγούμενο. Το πλήρες threat model είναι στο [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

### Πριν από την αλλαγή

**Preflight.** Κάθε έλεγχος έχει κωδικό και διάγνωση που ένας άνθρωπος μπορεί να ακολουθήσει. Το `apply` σταματά σε κάθε blocker. Οι άλλες εντολές που κάνουν preflight (`plan`, `verify`, `rollback`, `drift`, `install-drift`, `remove-drift`) σταματούν μόνο στα PF01 έως PF04, ώστε να δουλεύουν και σε VM χωρίς Secure Boot ή TPM.

| Κωδικός | Έλεγχος | Αν αποτύχει |
|---|---|---|
| PF01 | Τρέχει ως Administrator | Άνοιξε το Windows PowerShell με «Run as administrator» |
| PF02 | 64-bit Windows και 64-bit PowerShell (σε 32-bit PowerShell οι εγγραφές registry θα πήγαιναν στο Wow6432Node) | Ξεκίνα το 64-bit Windows PowerShell. Τα 32-bit Windows δεν υποστηρίζονται |
| PF03 | Build από 26200 έως 26999 | Ενημέρωσε τα Windows. Για νεότερο build: `-AllowUntestedBuild`, με δική σου ευθύνη |
| PF04 | Έκδοση Home | `-AllowOtherEdition`, με δική σου ευθύνη |
| PF05 | Καμία εκκρεμής επανεκκίνηση | Κάνε επανεκκίνηση και ξανατρέξε, ή `-IgnorePendingReboot` |
| PF06 | Secure Boot ενεργό | Ενεργοποίησέ το στο UEFI (το εργαλείο δεν το αλλάζει ποτέ), ή `-AllowPlatformGaps` |
| PF07 | Ενεργό TPM 2.0 | Ενεργοποίησε fTPM ή PTT στο UEFI, ή `-AllowPlatformGaps` |
| PF08 | Προειδοποίηση: BitLocker ή Device Encryption στον δίσκο συστήματος | Βεβαιώσου ότι έχεις το recovery key |
| PF09 | Προειδοποίηση: τρέχει ως SYSTEM | Τα audits που διαβάζουν HKCU παραλείπονται· ο έλεγχος κατάστασης καλύπτει κάθε profile |

**Λίστα που δεν αγγίζεται.** Το `policy/never-touch.json` είναι κώδικας: entry που αγγίζει κάτι από αυτά απορρίπτεται από τον validator (R07) και ξανά από τον engine όταν φορτώνει τα manifests. Ένα manifest set με οποιοδήποτε πρόβλημα απορρίπτεται ολόκληρο. Τα κοινά vectors `tests/vectors/never-touch.json` τρέχουν και στις δύο υλοποιήσεις (Python και PowerShell).

| Κατηγορία | Τι προστατεύεται |
|---|---|
| Υπηρεσίες (34) | Windows Update, servicing και εγκατάσταση (`wuauserv`, `UsoSvc`, `WaaSMedicSvc`, `BITS`, `TrustedInstaller`, `CryptSvc`, `msiserver`), Store (`ClipSVC`, `AppXSvc`, `InstallService`, `LicenseManager`), updater του Edge, Defender και Security Center, firewall (`mpssvc`, `BFE`), BitLocker (`BDESVC`), ταυτότητα και TPM (`wlidsvc`, `TokenBroker`, `TBS`), βασική υποδομή (`EventLog`, `RpcSs`, `Winmgmt`, `Schedule`, `gpsvc` και άλλες) |
| Εφαρμογές AppX (21 μοτίβα) | Store, App Installer, πακέτα runtime (`WindowsAppRuntime`, `UI.Xaml`, `VCLibs`, `NET.Native`), είσοδος και λογαριασμοί (`CloudExperienceHost`, `AAD.BrokerPlugin`, `AccountsControl`), κελύφη (Shell, Start, Search, `Client.*`) και Security Health UI |
| Scheduled tasks (13 μοτίβα) | `WindowsUpdate`, `UpdateOrchestrator`, `WaaSMedic`, `Servicing`, `InstallService`, `Windows Defender`, `BitLocker`, `TPM`, `PI`, `SoftwareProtectionPlatform`, `Clip`, `License Manager` και το task του Edge update |
| Registry | 10 κλειδιά (Secure Boot, Windows Update, BitLocker, TPM, Store, EdgeUpdate) και 7 ομάδες τιμών που θα απενεργοποιούσαν Defender (και Tamper Protection), SmartScreen ή το vulnerable driver blocklist |
| Optional features (1) | `Windows-Defender-Default-Definitions` |

Οι ρυθμίσεις του Defender (10 preferences, 16 ASR κανόνες) και τα audit policy subcategories (13) λειτουργούν αντίστροφα, ως allow-list: επιτρέπονται μόνο όσα αναφέρονται ρητά, και μόνο προς πιο ισχυρή προστασία ή πιο πλούσιο ίχνος. Ο καθαρισμός αρχείων επιτρέπεται μόνο στους 7 φακέλους της λίστας `cleanup`.

**Πύλες.** Entries με ρίσκο που δεν πρέπει να αποφασίζεται σιωπηλά μένουν εκτός `apply` μέχρι να ανοίξει ρητά μια πύλη. Το `plan` τα δείχνει ως `BLOCKED` με τον λόγο.

| Πύλη | Τι κρατά εκτός | Entries | Άνοιγμα |
|---|---|---|---|
| `deletes_user_data` | Entries που σβήνουν δεδομένα χρήστη που κανένα rollback δεν επαναφέρει | `appx-006` (Sticky Notes), `appx-007` (Microsoft To Do) | `-AcceptDataLoss` |
| `servicing_adjacent` | Entries που αγγίζουν στοιχεία κοντά στο servicing των Windows | `tel-008` (task Compatibility Appraiser) | `-AllowServicingAdjacent` |
| `requires_hardware` | Entries που χρειάζονται υλικό: virtualization για το `plt-011`, ενεργός Defender για τα `def-001` έως `def-028` | 29 | Κανένα flag: μένουν blocked όσο το υλικό λείπει |

Επιπλέον, 14 entries έχουν `requires_reboot`: το plan σημειώνει ότι το αποτέλεσμα φαίνεται μετά από επανεκκίνηση.

### Κατά την αλλαγή

- **Selftest.** Τα `apply`, `drift` και `install-drift` τρέχουν πρώτα το `selftest`. Αν αποτύχει, ο engine δεν αλλάζει το σύστημα (κωδικός 3).
- **Έγκριση.** Το id του plan είναι τα πρώτα 12 ψηφία ενός hash που καλύπτει το profile, τα manifests, τις πύλες και, για κάθε entry που αλλάζει, κάθε στόχο με την τιμή πριν και μετά. Αν κάτι από αυτά αλλάξει, το id αλλάζει, και το `-Yes` με το παλιό id αρνείται να αλλάξει οτιδήποτε. Διαδραστικά ζητείται η λέξη `APPLY`.
- **Transaction και journal.** Κάθε entry είναι ομάδα: η προηγούμενη κατάσταση κάθε στόχου γράφεται στο journal πριν από την αλλαγή, η αλλαγή διαβάζεται πίσω, και αν αποτύχει ένα βήμα επανέρχονται όλοι οι στόχοι του entry πριν ξεκινήσει το επόμενο. Κάθε εγγραφή του journal φέρει HMAC-SHA256 πάνω στο περιεχόμενό της και στο MAC της προηγούμενης: διαγραφή, αναδιάταξη ή αλλαγή γραμμής φαίνεται. Αν η επαλήθευση του journal αποτύχει, ο engine δεν γράφει σε αυτό ούτε κάνει rollback.
- **Σημείο επαναφοράς.** Δημιουργείται πριν από το `apply`, ως best effort. Το πραγματικό rollback είναι το journal.
- **Μία εκτέλεση τη φορά.** Mutex ανά μηχάνημα (`Global\winharden-engine`). Ο φάκελος κατάστασης γράφεται μόνο από SYSTEM και Administrators.

### Μετά την αλλαγή

- **Επαλήθευση.** Το `apply` τελειώνει με `verify` ([Επαλήθευση και αναφορές](#επαλήθευση-και-αναφορές)).
- **Rollback.** Επαναφέρει κάθε στόχο που καταγράφηκε μετά το checkpoint στην κατάσταση που είχε τότε, ξεκινώντας από την πιο πρόσφατη εγγραφή. Η επαναφορά μιας καταγεγραμμένης κατάστασης είναι idempotent, οπότε εγγραφές transaction που είχαν ήδη επανέλθει δεν βλάπτουν. Μετά διαβάζει ξανά κάθε στόχο και αναφέρει όσους διαφέρουν.

### Τι δεν εγγυάται

- Το journal είναι ένδειξη παραποίησης (tamper-evidence) απέναντι σε όποιον δεν είναι administrator. Ένας administrator μπορεί να ξαναγράψει και το κλειδί και το journal.
- Οι αφαιρεμένες εφαρμογές δεν επανέρχονται από τον engine: ξαναμπαίνουν από το Store. Τα διαγραμμένα αρχεία δεν επανέρχονται. Και τα δύο δηλώνονται `partial`.
- Το `selftest` ελέγχει τη λογική του engine πάνω σε σύστημα στη μνήμη. Δεν αποδεικνύει ότι τα Windows δέχονται κάθε εγγραφή: αυτό το κάνουν το `verify` και το [`docs/VERIFY-PROTOCOL.md`](docs/VERIFY-PROTOCOL.md).
- Τα manifests είναι κώδικας που τρέχει ως Administrator. Ο lint των audits και η λίστα never-touch πιάνουν λάθη, δεν αντικαθιστούν το review, και δεν υπάρχει υπογραφή των manifests.
- Η Microsoft μπορεί να επαναφέρει ή να αγνοήσει ρυθμίσεις με ένα update. Το drift task το εντοπίζει, δεν το αποκλείει.

## Επαλήθευση και αναφορές

Το `verify` ελέγχει κάθε entry του profile που δίνεις με δύο ανεξάρτητους τρόπους:

1. **Έλεγχος κατάστασης.** Ο engine διαβάζει κάθε στόχο (για `scope: user`, κάθε profile χρήστη) και τον συγκρίνει με το manifest.
2. **Audit.** Τρέχουν οι read-only εντολές του manifest και η έξοδός τους συγκρίνεται με την αναμενόμενη τιμή. Κάθε εντολή περνά πρώτα από lint (μία γραμμή, μόνο single quotes, λίστα επιτρεπτών ρημάτων, χωρίς aliases, native exes, redirections ή δίκτυο· εξαίρεση το `auditpol /get`) και τρέχει σε runspace ConstrainedLanguage. Αν το cmdlet της εντολής δεν βρίσκεται εκεί, όπως παρατηρήθηκε στη VM με modules που στηρίζονται σε CIM (Defender, ScheduledTasks, NetSecurity), η εντολή ξανατρέχει μία φορά σε runspace FullLanguage, μετά τον lint, που τότε είναι το μόνο φράγμα (D21).

| Κατάσταση entry | Σημασία |
|---|---|
| `pass` | Όλοι οι έλεγχοι συμφωνούν με το manifest |
| `fail` | Ένας στόχος δεν είναι στην επιθυμητή κατάσταση, ή ένα audit επιστρέφει άλλη τιμή. Ο λόγος γράφεται στην αναφορά |
| `error` | Ένας στόχος δεν διαβάζεται, ή ένα audit δεν μπόρεσε να τρέξει |
| `na` | Δεν ισχύει εδώ: άλλο build ή έκδοση, υλικό που λείπει, ή κανένας στόχος δεν υπάρχει στο σύστημα (υπηρεσία ή task που δεν υπάρχει) |
| `manual` | Θέλει άνθρωπο: το εργαλείο δεν αλλάζει ούτε ελέγχει τη ρύθμιση. Τα βήματα είναι στην αναφορά |

Τι πρέπει να ξέρεις όταν διαβάζεις το αποτέλεσμα:

- Το `verify` ελέγχει μόνο το profile που δίνεις και, χωρίς `-Profile`, μόνο το 1. Μετά από `apply -Profile 3` τρέξε `verify -Profile 3`.
- Το `verify` συγκρίνει πάντα το σύστημα με το manifest, όχι με ό,τι έκανε το `apply`. Ένα entry που το `apply` παραλείπει επειδή μια πύλη είναι κλειστή βγαίνει `fail`, και ο λόγος λέει ποια πύλη (`Apply skips this entry: …`, D22).
- Ένα audit μπορεί να παραλειφθεί (`skipped`) χωρίς να αλλάξει την κατάσταση του entry: όταν η εντολή εξαρτάται από τη γλώσσα και τα Windows δεν είναι στα αγγλικά (13 από τα 203 audits), και όταν το εργαλείο τρέχει ως SYSTEM και η εντολή διαβάζει HKCU. Τότε το entry κρίνεται από τον έλεγχο κατάστασης.
- Τα entries `attest` (9) ελέγχονται μόνο με audits και δεν αλλάζουν ποτέ. Τα `once` (καθαρισμός) δεν έχουν κατάσταση να ελεγχθεί: το `apply` τυπώνει τι έκανε.
- Ο κωδικός εξόδου είναι 1 όταν υπάρχει έστω ένα `fail` ή `error`.

Το `verify` (και το `apply` στο τέλος του) γράφει τέσσερα αρχεία στο `%ProgramData%\winharden\reports\<run>`, ή στον φάκελο του `-OutDir`:

| Αρχείο | Περιεχόμενο |
|---|---|
| `winharden-report.json` | Πλήρες αποτέλεσμα, για μηχανική ανάγνωση |
| `winharden-report.html` | Το ίδιο για ανθρώπους |
| `winharden-poam.csv` | Πρότυπο POA&M για τις εξαιρέσεις, δηλαδή ό,τι δεν συμφωνεί |
| `winharden-xccdf.xml` | Ελάχιστη εξαγωγή αποτελεσμάτων σε XCCDF 1.2 |

Οι αναφορές είναι τοπικά αρχεία και δεν ανεβαίνουν πουθενά. Κάθε αναφορά φέρει την έκδοση και το code fingerprint του engine, το όνομα του υπολογιστή, τη λίστα των ορίων της (για παράδειγμα ότι για τα `unverified` το `pass` σημαίνει «η τιμή γράφτηκε και διαβάζεται πίσω», όχι «τα Windows την τηρούν») και, σε κάθε profile, μια γραμμή για το Recall: `attested-off`, `not-attested`, ή `not-checked` όταν το `ai-004` δεν ήταν μέρος του run.

## Αρχεία που γράφει το εργαλείο

```text
%ProgramData%\winharden\            μόνο SYSTEM και Administrators
  journal\journal.jsonl             αλυσίδα HMAC-SHA256: before-states, checkpoints
  journal\journal.key               το κλειδί της αλυσίδας
  plans\plan-<id>.json              κάθε plan που εμφανίστηκε
  reports\<run>\                    winharden-report.json|html, winharden-poam.csv, winharden-xccdf.xml
  logs\winharden.jsonl              δομημένο log, ένα JSON ανά γραμμή
  drift-state.json                  αποτέλεσμα της τελευταίας εκτέλεσης του drift task
%ProgramFiles%\winharden\           αντίγραφο του εργαλείου για το drift task (μόνο μετά από install-drift)
```

Ο έλεγχος πρόσβασης χρησιμοποιεί well-known SIDs, ώστε να δουλεύει σε κάθε γλώσσα των Windows.

## Παρακολούθηση drift

Μετά από update τα Windows μπορούν να επαναφέρουν ρυθμίσεις και εφαρμογές. Το `install-drift` εγκαθιστά ένα task που το εντοπίζει.

- **Τι τρέχει.** Task `\winharden\winharden-drift`, ως SYSTEM, κάθε Κυριακή στις 03:00 και σε κάθε εκκίνηση, για το profile (και τα `-Exclude` και `-OptIn`) που δόθηκαν στο `install-drift`. Εκτελεί το `drift`: `verify`, αναφορά, και αποθήκευση του αποτελέσματος στο `drift-state.json`. Αν το build άλλαξε από την προηγούμενη εκτέλεση (feature update), το αναφέρει.
- **Μόνο επαλήθευση.** Εκτός αν η εγκατάσταση έγινε με `-Reapply`: τότε ξαναεφαρμόζει όσα ξέφυγαν, ποτέ entries που σβήνουν δεδομένα (το task δεν παίρνει ποτέ `-AcceptDataLoss`). Το `-AllowServicingAdjacent` περνά στο task μόνο αν δοθεί στην εγκατάσταση.
- **Προστασία.** Ένα task SYSTEM που τρέχει scripts είναι δρόμος ανύψωσης δικαιωμάτων αν ένας απλός χρήστης μπορεί να τα αλλάξει. Τα αρχεία αντιγράφονται σε φάκελο του Program Files, και αν κάποιος εκτός από SYSTEM, Administrators, TrustedInstaller και CREATOR OWNER μπορεί να γράψει εκεί, η εγκατάσταση αποτυγχάνει πριν καταχωριστεί το task.
- **Όπως το `verify`.** Entries που κρατά εκτός `apply` μια κλειστή πύλη εμφανίζονται ως αποτυχίες.
- **Έλεγχος.** Το `status` δείχνει αν το task υπάρχει και την τελευταία εκτέλεση. Το `remove-drift` το αφαιρεί.

Το drift task δεν έχει δοκιμαστεί σε Windows ([Κατάσταση](#κατάσταση)).

## Manifests

Ένα αρχείο ανά module στο `manifests/`. Κάθε ρύθμιση είναι ακριβώς ένα entry, με id που δεν αλλάζει και δεν ξαναχρησιμοποιείται: `<prefix>-<3 ψηφία>-<όνομα>`.

### Πεδία ενός entry

| Πεδίο | Υποχρεωτικό | Τι λέει |
|---|---|---|
| `id`, `module`, `title` | ναι | Ταυτότητα του entry |
| `tier` | ναι | Βαθμίδα εμπιστοσύνης του μηχανισμού (παρακάτω) |
| `min_profile` | ναι | Από ποιο profile και πάνω μπαίνει (1, 2 ή 3) |
| `opt_in` | όχι | Αν υπάρχει, το entry μπαίνει μόνο με `-OptIn <όνομα>` |
| `mode` | ναι | Τι κάνει ο engine (παρακάτω) |
| `home_effective` | ναι | Αν το αποτέλεσμα έχει παρατηρηθεί σε Home (παρακάτω) |
| `verified` | όχι | Build, ημερομηνία, VM και παρατήρηση. Απαιτείται όταν `home_effective` είναι `verified` (R05) |
| `channel_class` | ναι | Το κανάλι αλλαγής: `csp`, `policy`, `cmdlet`, `settings-backing`, `unsupported` |
| `unsupported_justification` | όχι | Αιτιολόγηση, αν το κανάλι είναι `unsupported` (R04) |
| `applicability` | όχι | Εκδόσεις και ελάχιστο build |
| `requires_hardware` | όχι | Υλικό που πρέπει να υπάρχει, αλλιώς το entry μένει blocked |
| `rationale`, `impact` | ναι | Γιατί, και τι θα αλλάξει για τον χρήστη |
| `apply` | όχι | Η λίστα των operations (παρακάτω) |
| `audit` | ναι | Read-only εντολές με αναμενόμενη τιμή (`checks`), ή `manual_check` |
| `rollback` | ναι | Στρατηγική και `reversibility` (`full` ή `partial`, με όριο) |
| `manual_steps` | όχι | Βήματα για τον χρήστη (mode `manual`) |
| `flags` | όχι | `servicing_adjacent`, `requires_reboot`, `deletes_user_data` |
| `risk` | ναι | `low`, `medium` ή `high` |
| `evidence`, `references` | ναι | Κάθε ισχυρισμός με βαθμό πηγής, και οι σύνδεσμοι |
| `notes` | όχι | Για τα `unverified`: πώς θα επαληθευτεί σε VM |

### Τιμές και κατανομή

| `mode` | Entries | Σημασία |
|---|---|---|
| `enforce` | 115 | Ο engine εφαρμόζει και ελέγχει |
| `once` | 4 | Μία φορά (καθαρισμός αρχείων): δεν υπάρχει κατάσταση να ελεγχθεί |
| `attest` | 9 | Μόνο έλεγχος και αναφορά, ποτέ αλλαγή |
| `manual` | 5 | Βήματα για τον χρήστη, ο engine τα αναφέρει |

| `home_effective` | Entries | Σημασία |
|---|---|---|
| `verified` | 0 | Παρατηρήθηκε σε Home (με build και ημερομηνία) |
| `expected` | 90 | Μηχανισμός ανεξάρτητος από την έκδοση: υπηρεσία, task, AppX, feature, ή τιμή που γράφει το ίδιο το Settings |
| `unverified` | 43 | Policy που το Home μπορεί να αγνοεί. Το `notes` λέει πώς να επαληθευτεί |
| `na` | 0 | Δεν ισχύει στο Home, οπότε δεν εφαρμόζεται (R14) |

| `tier` | Entries | Σημασία |
|---|---|---|
| `T0` | 23 | Υποστηριζόμενος μηχανισμός, αποτέλεσμα στο Home αναμενόμενο ή παρατηρημένο. Θέλει πηγή `ms-doc` ή `ms-statement` (R03) |
| `T1` | 110 | Τεκμηριωμένο ή ευρέως χρησιμοποιούμενο, αναστρέψιμο. Το αποτέλεσμα στο Home μπορεί να είναι `unverified` |
| `T2` | 0 | Μη υποστηριζόμενο κανάλι ή servicing-adjacent, μόνο profile 3 (R02, R04) |

| `risk` | Entries | Σημασία |
|---|---|---|
| `low` | 92 | Από το profile 1 |
| `medium` | 32 | Από το profile 2 |
| `high` | 9 | Μόνο στο profile 3 |

Οι βαθμοί πηγής (`evidence[].grade`) λένε πόσο να εμπιστευτείς κάθε ισχυρισμό:

| Βαθμός | Σημασία |
|---|---|
| `ms-doc` | Τεκμηρίωση της Microsoft για τη ρύθμιση |
| `ms-doc-nonhome` | Τεκμηρίωση της Microsoft που δεν κατονομάζει το Home (π.χ. μόνο Pro, Enterprise, Education). Το entry είναι τότε `unverified` |
| `ms-statement` | Δήλωση της Microsoft εκτός της τεκμηρίωσης της ρύθμισης: blog, ανακοίνωση, απάντηση |
| `third-party` | Τρίτη πηγή με μέθοδο, π.χ. audit item ενός benchmark |
| `community` | Φόρουμ, tutorial, λίστα ή script άλλου εργαλείου |
| `background` | Προηγούμενη γνώση που δεν ξαναελέγχθηκε. Δηλώνεται ρητά |

### Operations

| Τύπος | Operations | Τι αλλάζει |
|---|---|---|
| `registry` | 66 | Τιμή registry, σε HKLM ή HKCU (για HKCU: κάθε υπάρχον profile και το Default user hive) |
| `setting` | 39 | Defender preference, ASR κανόνας ή audit policy subcategory (allow-list) |
| `appx` | 31 | Αφαίρεση πακέτου για όλους τους χρήστες: το εγκατεστημένο και το provisioned |
| `service` | 7 | Τρόπος εκκίνησης και κατάσταση υπηρεσίας |
| `scheduled_task` | 7 | Απενεργοποίηση task |
| `file_cleanup` | 7 | Καθαρισμός αρχείων παλαιότερων από μία ημέρα, μόνο σε φακέλους της allow-list |
| `optional_feature` | 3 | Απενεργοποίηση Windows optional feature |

### Παράδειγμα

<details>
<summary>Το entry <code>tel-001-diagnostic-data-required</code>, με μία πηγή και ένα link αντί για όλες</summary>

```json
{
  "id": "tel-001-diagnostic-data-required",
  "module": "m1-telemetry",
  "title": "Pin diagnostic data to Required",
  "tier": "T1",
  "min_profile": 1,
  "mode": "enforce",
  "home_effective": "unverified",
  "channel_class": "policy",
  "applicability": {
    "editions": [
      "Home"
    ],
    "min_build": 26200
  },
  "rationale": "Windows 11 Home offers only Required and Optional diagnostic data and cannot switch collection off. Pinning the Allow Diagnostic Data policy to 1 (Required) keeps Optional data off. Level 0 is not used: Microsoft documents it as honoured only on Enterprise, Education and Server editions and equal to 1 elsewhere.",
  "impact": "The Optional diagnostic data switch in Settings becomes locked and may show a managed-by-your-organization notice. Windows Insider enrollment, which needs Optional data, is blocked.",
  "apply": [
    {
      "type": "registry",
      "hive": "HKLM",
      "path": "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
      "name": "AllowTelemetry",
      "kind": "DWord",
      "data": 1,
      "scope": "machine"
    }
  ],
  "audit": {
    "checks": [
      {
        "command": "(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name AllowTelemetry -ErrorAction SilentlyContinue).AllowTelemetry",
        "expected": "1"
      }
    ]
  },
  "rollback": {
    "strategy": "journal",
    "reversibility": "full"
  },
  "risk": "low",
  "evidence": [
    {
      "grade": "ms-doc-nonhome",
      "source": "learn.microsoft.com Policy CSP System, AllowTelemetry (read 2026-11-10)",
      "claim": "Documented for Pro, Enterprise, Education and IoT only; Home is not listed. Level 0 applies only to Enterprise, Education, IoT and Server and is equivalent to 1 on other devices."
    }
  ],
  "references": [
    {
      "title": "Policy CSP - System (AllowTelemetry)",
      "url": "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-system"
    }
  ]
}
```

</details>

### Κανόνες του validator

Το `tools/validate_manifests.py` εφαρμόζει το schema (`schema/manifest.schema.json`) και 21 κανόνες πάνω από αυτό.

<details>
<summary>Οι κανόνες R01 έως R21</summary>

| Κανόνας | Τι επιβάλλει |
|---|---|
| R01 | Το id είναι μοναδικό |
| R02 | Το tier T2 μπαίνει μόνο στο profile 3 |
| R03 | Το T0 θέλει πηγή `ms-doc` ή `ms-statement`, `home_effective` `verified` ή `expected`, και όχι μη υποστηριζόμενο κανάλι |
| R04 | Μη υποστηριζόμενο κανάλι σημαίνει T2 και αιτιολόγηση τουλάχιστον 40 χαρακτήρων |
| R05 | Το `home_effective: verified` θέλει το αντικείμενο `verified` με build και ημερομηνία |
| R06 | Τα `enforce` και `once` έχουν `apply`, τα `attest` και `manual` δεν έχουν, και το `manual` έχει `manual_steps` |
| R07 | Κανένα operation δεν αγγίζει τη λίστα never-touch ή βγαίνει από τις allow-lists (settings, φάκελοι καθαρισμού) |
| R08 | Η μερική αναστρεψιμότητα δηλώνει όριο (τουλάχιστον 20 χαρακτήρες), και η αφαίρεση AppX είναι πάντα `partial` |
| R09 | Δεν υπάρχουν διπλοί σύνδεσμοι στις πηγές |
| R10 | Κάθε εντολή audit περνά τον lint (μία γραμμή, single quotes, μόνο read-only ρήματα, χωρίς aliases και δίκτυο) |
| R11 | Το hive ταιριάζει με το `scope` (HKLM με machine, HKCU με user) |
| R12 | Στοιχείο κοντά στο servicing θέλει `flags.servicing_adjacent` και profile 3 |
| R13 | Το `module` του entry είναι αυτό του αρχείου |
| R14 | Το `home_effective: na` δεν εφαρμόζεται |
| R15 | Τα δεδομένα ταιριάζουν με το `kind` (και το `merge: hide-list` θέλει String που ξεκινά με `hide:`) |
| R16 | Το ρίσκο θέλει ελάχιστο profile: `medium` από το 2, `high` από το 3 |
| R17 | Τα `enforce` και `attest` έχουν `audit.checks`, το `once` έχει checks ή `manual_check`, το `manual` έχει `manual_check` |
| R18 | Το `deletes_user_data` ισχύει μόνο για `enforce` και `once` και δεν μπορεί να είναι `full` |
| R19 | Το `once` ισχύει μόνο για καθαρισμό αρχείων, με `partial` αναστρεψιμότητα, και ο καθαρισμός θέλει `once` |
| R20 | Wildcard επιτρέπεται μόνο στο τελευταίο τμήμα της διαδρομής, κάτω από σταθερό γονικό κλειδί, και όχι μαζί με `merge` |
| R21 | Η τιμή ενός `setting` έχει τον σωστό τύπο JSON για το `kind` |

</details>

## Αρχιτεκτονική

```text
winharden.ps1      CLI: εντολές, έγκριση, κωδικοί εξόδου
engine/            ο engine: Windows PowerShell 5.1, μόνο ASCII, χωρίς εξαρτήσεις
manifests/         10 αρχεία JSON, ένα ανά module
schema/            manifest.schema.json
policy/            never-touch.json
tools/             validator, στατικός έλεγχος του engine, γεννήτριες
tests/             tests σε Python και κοινά vectors
docs/              έγγραφα
```

Η ροή μιας εκτέλεσης:

```text
manifests/*.json + policy/never-touch.json
        |   φόρτωση: schema, never-touch, audit lint (σφάλμα = απορρίπτεται όλο το σύνολο)
        v
   επιλογή entries (profile, -Only, -Exclude, -OptIn, applicability, πύλες)
        |
        v
      plan  ---- έγκριση (APPLY ή -Yes -PlanId) ---->  apply: journal, αλλαγή, ανάγνωση πίσω
        |                                                |
        +--------------------> verify <------------------+
                                  |
                               αναφορές
```

Ο engine μιλά με το σύστημα μόνο μέσα από έναν πίνακα συναρτήσεων, τον provider. Το `Provider.Real.ps1` είναι το μόνο αρχείο που αγγίζει registry, υπηρεσίες, tasks, AppX, features, user hives και το runspace των audits. Το `Provider.Fake.ps1` είναι ένα σύστημα στη μνήμη: το `selftest` τρέχει τον ίδιο κώδικα engine πάνω του και δεν αλλάζει ποτέ το μηχάνημα.

| Αρχείο | Ρόλος |
|---|---|
| `Core.ps1` | Κοινά βοηθητικά: log, φάκελος κατάστασης και ACL, code fingerprint |
| `Policy.ps1` | Η λίστα never-touch και ο lint των audits στο runtime |
| `Manifest.ps1` | Φόρτωση manifests και επανέλεγχος όσων ελέγχει ο validator |
| `Provider.ps1` | Το όριο ανάμεσα στον engine και το σύστημα: ο πίνακας των συναρτήσεων |
| `Provider.Real.ps1` | Το πραγματικό σύστημα (και το runspace των audits) |
| `Provider.Fake.ps1` | Σύστημα στη μνήμη για το `selftest`, με ένθεση σφαλμάτων |
| `Journal.ps1` | Append-only journal με HMAC, και το mutex |
| `Plan.ps1` | Χτίζει το plan: διαβάζει, δεν αλλάζει τίποτα |
| `Apply.ps1` | Εφαρμόζει το plan ανά entry, και το σημείο επαναφοράς |
| `Rollback.ps1` | Επαναφορά σε checkpoint |
| `Verify.ps1` | Έλεγχος κατάστασης και audits |
| `Report.ps1` | Αναφορές JSON, HTML, CSV και XCCDF |
| `Preflight.ps1` | Οι έλεγχοι PF01 έως PF09 |
| `Drift.ps1` | Εγκατάσταση και εκτέλεση του drift task |
| `SelfTest.ps1` | Τα tests του engine πάνω στον fake provider |

## Ανάπτυξη και έλεγχοι

Απαιτείται Python 3 (έχει δοκιμαστεί με 3.13), με `jsonschema` και `pytest`. Το PowerShell του engine δεν εκτελείται εκεί που αναπτύσσεται.

```text
pip install -r tools/requirements.txt pytest
python3 -I tools/validate_manifests.py
python3 -I tools/check_engine.py
python3 -I tools/gen_reference.py --check
python3 -I tools/sync_lint_vectors.py --check
python3 -m pytest -q
```

| Εργαλείο | Τι ελέγχει |
|---|---|
| `tools/validate_manifests.py` | Schema, κανόνες R01 έως R21, never-touch και audit lint σε όλα τα manifests |
| `tools/check_engine.py` | Τον κώδικα PowerShell ως κείμενο: ASCII, σύνταξη 5.1, ισορροπία αγκυλών, κλήσεις προς συναρτήσεις και παραμέτρους που δεν υπάρχουν, μεταβλητές που διαβάζονται χωρίς να οριστούν, τιμές που διαρρέουν στην έξοδο, διαφωνίες των provider tables |
| `tools/gen_reference.py` | Παράγει το `docs/REFERENCE.md` από τα manifests (`--check` για έλεγχο) |
| `tools/sync_lint_vectors.py` | Κρατά πλήρη τα κοινά vectors του audit lint: κάθε εντολή audit των manifests πρέπει να υπάρχει εκεί (`--check`) |
| `python3 -m pytest` | Όλα τα παραπάνω ως tests. Επιπλέον: tests που σπάνε σκόπιμα ένα έγκυρο entry ή ένα αντίγραφο του engine και απαιτούν να το πιάσει ο έλεγχος, τα κοινά vectors και η ισοδυναμία των δύο linters |

Οι στατικοί έλεγχοι είναι δίχτυ ασφαλείας, όχι απόδειξη. Την απόδειξη για τη λογική του engine τη δίνει το `selftest` στα Windows, και για τις πραγματικές εγγραφές το [`docs/VERIFY-PROTOCOL.md`](docs/VERIFY-PROTOCOL.md).

**Συμβάσεις**

- Κάθε αλλαγή συμπεριφοράς έρχεται με το manifest entry (ή την αλλαγή του) και το test που την αποδεικνύει.
- Αρχεία engine: σύνταξη Windows PowerShell 5.1, μόνο ASCII (το 5.1 διαβάζει script χωρίς BOM ως ANSI), μόνο LF, χωρίς tabs. Το code fingerprint είναι hash των bytes των αρχείων, και το `.gitattributes` κρατά LF και σε checkout στα Windows.
- Οι κλήσεις προς το σύστημα περνούν μόνο από τον provider (`Invoke-WhProv 'Όνομα' …`). Κάθε κλήση που μπορεί να επιστρέψει συλλογή τυλίγεται σε `@( )`.
- Κώδικας στο `SelfTest.ps1`: ένα ψευδές λάθος εκεί μπλοκάρει το `apply` σε κάθε μηχάνημα (D20), οπότε προστίθεται με ιδιαίτερη προσοχή.
- Κάθε απόφαση που πάρθηκε χωρίς να ρωτηθεί ο κάτοχος καταγράφεται στο `docs/DECISIONS.md`, με λόγο και τρόπο αλλαγής.

**Νέο entry**

1. Διάλεξε module και επόμενο id. Γράψε το entry με αιτιολόγηση, επίπτωση, πηγές με βαθμό και, για `unverified`, τα `notes`.
2. Γράψε το audit ως μία γραμμή read-only με single quotes.
3. `python3 -I tools/validate_manifests.py`, μετά `python3 -I tools/sync_lint_vectors.py` και `python3 -I tools/gen_reference.py`.
4. `python3 -m pytest -q`. Οι αριθμοί σε αυτό το README (σύνολα, profiles, κατανομές) γράφονται με το χέρι: αν το entry τους αλλάζει, ενημέρωσέ τους.
5. Δοκίμασέ το σε VM με το [`docs/VERIFY-PROTOCOL.md`](docs/VERIFY-PROTOCOL.md) πριν γίνει `verified`.

## Αντιμετώπιση προβλημάτων

| Σύμπτωμα | Αιτία | Τι κάνεις |
|---|---|---|
| `Stopped before doing anything. Nothing was changed.` | Απέτυχε ένας έλεγχος preflight | Δες τον κωδικό PF στον πίνακα του [Μοντέλου ασφαλείας](#μοντέλο-ασφαλείας) |
| `Self test FAILED (… checks). The engine will not change this system.` | Τα tests του engine απέτυχαν σε αυτό το μηχάνημα | Τρέξε `selftest` για την πλήρη λίστα και στείλε την έξοδο με το code fingerprint. Το `-SkipSelfTest` δεν συνιστάται |
| `The journal failed verification…` | Το journal άλλαξε έξω από το εργαλείο ή είναι κατεστραμμένο | Κράτησε αντίγραφο του `%ProgramData%\winharden`. Χρησιμοποίησε `-TrustJournal` μόνο αν είσαι βέβαιος ότι κανείς δεν το άλλαξε |
| `Another winharden run is in progress on this machine.` | Τρέχει ήδη μια εκτέλεση, ίσως το drift task | Περίμενε να τελειώσει |
| `-Yes needs -PlanId …` | Το `-PlanId` λείπει ή δεν ταιριάζει με το τρέχον plan: το σύστημα ή οι επιλογές άλλαξαν | Τρέξε ξανά `plan`, έλεγξέ το και δώσε το νέο id |
| `Nothing to change: …` | Όλα τα επιλεγμένα entries συμφωνούν ήδη, δεν ισχύουν ή είναι blocked | Φυσιολογικό. Το `apply` κάνει μόνο `verify` και δεν δημιουργεί checkpoint |
| Το `verify` δείχνει λίγα entries | Ελέγχει μόνο το profile 1 αν δεν δοθεί `-Profile` | `verify -Profile N`, με το ίδιο N που εφάρμοσες |
| `FAIL` με `Apply skips this entry: …` (π.χ. `appx-006`, `appx-007`, `tel-008`) | Κλειστή πύλη: το `apply` δεν αγγίζει το entry | `-AcceptDataLoss` ή `-AllowServicingAdjacent` στο `plan` και στο `apply`, ή αποδοχή του FAIL |
| `ERROR` ή `FAIL` σε `plt-001` έως `plt-004` σε VM (π.χ. `Cmdlet not supported on this platform`) | Τα entries αυτά είναι `attest`: δείχνουν την κατάσταση της πλατφόρμας. Η VM δεν είναι UEFI, δεν έχει TPM 2.0 ή κρυπτογράφηση | Όριο της VM, όχι αποτυχία του `apply`. Ελέγχονται σε πραγματικό υλικό |
| `FAIL` στο `plt-011` (memory integrity) αφού γράφτηκε η τιμή | Η τιμή γράφτηκε αλλά η λειτουργία δεν τρέχει ακόμη: το αποτέλεσμα φαίνεται μετά από επανεκκίνηση | Επανεκκίνηση και νέο `verify`. Αν παραμένει, δες το `impact` του entry: ασύμβατοι drivers ή υλικό χωρίς υποστήριξη |
| `FAILED    <entry>: … (reverted)` στο `apply` | Ένα βήμα του entry απέτυχε και το entry επανήλθε ολόκληρο | Ο λόγος είναι στην ίδια γραμμή και στο `logs\winharden.jsonl` |
| Audits `skipped` | Η εντολή εξαρτάται από τη γλώσσα και τα Windows δεν είναι στα αγγλικά, ή το εργαλείο τρέχει ως SYSTEM | Φυσιολογικό: το entry κρίνεται από τον έλεγχο κατάστασης |

## Ασφάλεια και αναφορά προβλημάτων

Το εργαλείο τρέχει ως Administrator και αλλάζει το σύστημα, οπότε ένα λάθος ή μια ευπάθεια έχει πραγματικό κόστος. Το [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) περιγράφει τι προστατεύεται, τους κινδύνους του ίδιου του εργαλείου και το υπολειπόμενο ρίσκο.

Το έργο δεν έχει ορίσει ακόμη κανάλι αναφοράς: οι αναφορές πηγαίνουν στον κάτοχο του repository. Για κάθε πρόβλημα βάλε:

- το code fingerprint (το δείχνει το banner κάθε εντολής εκτός από `help`, `list` και `selftest`, και κάθε αναφορά),
- το build των Windows και αν ήταν VM,
- την έξοδο της εντολής και, αν υπάρχει, το σχετικό κομμάτι του `logs\winharden.jsonl`.

Οι αναφορές και το log είναι τοπικά αρχεία με στοιχεία του μηχανήματος, όπως το όνομα του υπολογιστή: έλεγξέ τα πριν τα στείλεις σε τρίτους. Για ευπάθεια στο ίδιο το εργαλείο, π.χ. τρόπο να τρέξει μη εγκεκριμένος κώδικας ως SYSTEM, στείλε τα στοιχεία ιδιωτικά στον κάτοχο και όχι σε δημόσιο issue.

## Έγγραφα

| Έγγραφο | Περιεχόμενο |
|---|---|
| [`docs/REFERENCE.md`](docs/REFERENCE.md) | Πίνακας όλων των entries. Παράγεται από τα manifests, δεν επεξεργάζεται με το χέρι |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Οι αποφάσεις D1 έως D22 που πάρθηκαν χωρίς να ρωτηθεί ο κάτοχος, με λόγο και τρόπο αλλαγής |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Τι προστατεύεται, κίνδυνοι του ίδιου του εργαλείου, υπολειπόμενο ρίσκο |
| [`docs/VERIFY-PROTOCOL.md`](docs/VERIFY-PROTOCOL.md) | Πώς δοκιμάζεται σε VM και πώς ένα entry γίνεται `verified` |
| [`docs/BACKLOG.md`](docs/BACKLOG.md) | Τι δεν έγινε, τι μένει ανοιχτό, τι παραλείφθηκε και γιατί |
| [`docs/M4-CATALOG.md`](docs/M4-CATALOG.md) | Ο κατάλογος εφαρμογών AppX και οι κανόνες επιλογής του |

## Άδεια και ευθύνη

Το παρόν έργο διατίθεται υπό την Άδεια Χρήσης BSD 3 ρητρών. Δείτε [LICENSE](LICENSE).

**Ευθύνη.** Το εργαλείο αλλάζει ρυθμίσεις συστήματος ως Administrator και δεν δίνει εγγύηση για συγκεκριμένο αποτέλεσμα. Οι αλλαγές του profile 3 μπορεί να σπάσουν παλιά προγράμματα και drivers, και μερικές αλλαγές (αφαίρεση εφαρμογών, καθαρισμός αρχείων) δεν αναιρούνται πλήρως. Δοκίμασέ το πρώτα σε VM με snapshot και κράτα αντίγραφο ασφαλείας των δεδομένων σου.