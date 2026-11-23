# M4 AppX: κατάλογος για έγκριση

**Κατάσταση: υλοποιήθηκε στις 2026-11-13.** Το `manifests/m4-appx.json` έχει 30 entries: τα 23 αυτού του καταλόγου (3 / 10 / 10) και 7 παλιά πακέτα στο profile 3. Οι τρεις ερωτήσεις της ενότητας 9 απαντήθηκαν χωρίς ερώτηση, στο `docs/DECISIONS.md` (D1 έως D3). Ο κατάλογος μένει ως τεκμηρίωση της έρευνας και των πηγών· η αλήθεια για κάθε πακέτο είναι πλέον το manifest.

## 1. Πηγές (διαβάστηκαν στις 2026-11-12)

Οι σελίδες διαβάστηκαν με εργαλείο που επιστρέφει περίληψη. Γι' αυτό τα ονόματα ελέγχθηκαν σε περισσότερες από μία πηγές και οι παραθέσεις ζητήθηκαν αυτολεξεί. Στις 2026-11-12 οι S1, S3 και S4 ξαναδιαβάστηκαν για να ελεγχθούν ένα προς ένα τα ονόματα, οι ενότητες, οι τιμές και οι παραθέσεις αυτού του εγγράφου, και βρέθηκαν όλα. Η μόνη διαφορά ανάμεσα στις αναγνώσεις αφορά ένα όνομα εκτός καταλόγου: το `Microsoft.WindowsNotepad` φάνηκε στην πρώτη ανάγνωση της S4 και όχι στη δεύτερη, και καμία γραμμή δεν στηρίζεται σε αυτό. Καμία πηγή που διάβασα δεν λέει ποια πακέτα υπάρχουν στο Home: η S1 αφορά Enterprise και Education, και η μόνη που αναφέρει το Home, η S2, το κάνει για την policy και με «results may vary» (ενότητα 7).

| Κωδ. | Πηγή | Τι δίνει | Βαθμός |
|---|---|---|---|
| S1 | [Microsoft Support: Policy-Based Removal of Pre-installed Microsoft Store Apps](https://support.microsoft.com/en-us/servicing/os/windows/docs/2025/08/policy-based-removal-of-pre-installed-microsoft-store-apps) (15/8/2025) | 25 σύντομα αναγνωριστικά αφαιρέσιμων εφαρμογών και ποια είναι προεπιλεγμένα προς αφαίρεση. Ισχύει για Enterprise και Education 25H2 | `ms-doc-nonhome` |
| S2 | [allthings.how: οδηγός για την ίδια policy](https://allthings.how/remove-windows-11-bloatware-using-the-built-in-policy-24h2-25h2/) | Package family names των ίδιων εφαρμογών | `third-party` |
| S3 | [Win11Debloat, Appslist.txt](https://www.github.com/Raphire/Win11Debloat/blob/master/Appslist.txt) (δύο αναγνώσεις, συμφωνούν) | Ακριβή ονόματα σε τρεις ενότητες και σχόλια εξάρτησης | `community` |
| S4 | [tiny11builder, tiny11maker.ps1](https://www.Github.com/ntdevlabs/tiny11builder/blob/main/tiny11maker.ps1) | Δεύτερη, ανεξάρτητη λίστα ονομάτων που αφαιρούνται | `community` |
| S5 | Microsoft Learn: [Remove-AppxPackage](https://learn.microsoft.com/en-us/powershell/module/appx/remove-appxpackage), [Remove-AppxProvisionedPackage](https://learn.microsoft.com/en-us/powershell/module/dism/remove-appxprovisionedpackage) | Τι κάνουν τα cmdlets | `ms-doc` |
| S6 | [Microsoft Security Blog, Storm-1811 και Quick Assist](https://www.microsoft.com/en-us/security/blog/?p=134322) | Σύσταση για το Quick Assist | `ms-statement` |
| S7 | [WinUtil docs: Tweaks](https://winutil.christitus.com/dev/tweaks/) (δύο αναγνώσεις, συμφωνούν) | Ποια tweaks αφορούν εφαρμογές | `community` |

Στην S3 οι ενότητες είναι: **1** αφαιρείται από προεπιλογή, **2** δεν αφαιρείται εκτός αν βγάλεις το `#`, **3** αφαιρείται μόνο αν το επιλέξεις.

Η S1 είναι λίστα αναγνωριστικών της policy, όχι ονομάτων πακέτων (π.χ. `Todo` αντιστοιχεί στο πακέτο `Microsoft.Todos`, `MediaPlayer` στο `Microsoft.ZuneMusic`). Η αντιστοίχιση προέρχεται από τις S2 και S3.

## 2. Τι σημαίνει «classic» στα AppX

Το WinUtil (S7) δεν έχει επιλεκτική αφαίρεση εφαρμογών στα Essential Tweaks. Έχει μόνο «Disable ConsumerFeatures» (το καλύπτει το M2) και «Debloat Edge». Η μόνη αφαίρεση AppX είναι το «Remove ALL MS Store Apps - NOT RECOMMENDED» στα Advanced Tweaks (CAUTION), που το ίδιο το εργαλείο δεν συνιστά.

Άρα το profile 1 εδώ είναι δική μου συντηρητική ερμηνεία: μόνο εφαρμογές που (α) η Microsoft επιλέγει προς αφαίρεση στο δικό της sample (S1, τιμή `true`), (β) αφαιρούνται από προεπιλογή στην S3 και στην S4, και (γ) δεν έχουν σχόλιο εξάρτησης στις πηγές ούτε δεδομένα χρήστη.

## 3. Κανόνες του καταλόγου

1. Το όνομα είναι το ακριβές `Name` του πακέτου, χωρίς wildcards (το επιβάλλει ο validator).
2. Κάθε όνομα εμφανίζεται σε τουλάχιστον δύο από τις S2, S3, S4.
3. Κανένα όνομα δεν είναι στη never-touch λίστα (ελέγχεται μηχανικά).
4. Ό,τι έχει τεκμηριωμένη εξάρτηση ή δεδομένα χρήστη δεν μπαίνει στο profile 1.
5. Πακέτο που λείπει θεωρείται συμμορφωμένο, όχι σφάλμα.

## 4. Προτεινόμενα entries

Στήλη «Πηγές»: τα S2, S3 (με την ενότητα), S4 στα οποία βρέθηκε το όνομα. «Sample S1» είναι η προεπιλογή της Microsoft όπου υπάρχει.

### Profile 1 (3 entries)

| Πακέτο | Εφαρμογή | Πηγές | Σημείωση |
|---|---|---|---|
| `Microsoft.BingNews` | News | S2, S3 §1, S4 | Sample S1: `true`. Δεν τεκμηριώνεται εξάρτηση στις πηγές |
| `Microsoft.BingWeather` | Weather | S2, S3 §1, S4 | Sample S1: `true`. Δεν τεκμηριώνεται εξάρτηση στις πηγές. Να ελεγχθεί σε VM ότι τα Widgets και το lock screen δεν επηρεάζονται |
| `Microsoft.MicrosoftSolitaireCollection` | Solitaire Collection | S2, S3 §1, S4 | Sample S1: `true`. Δεν τεκμηριώνεται εξάρτηση στις πηγές |

Το `Microsoft.Copilot` είναι ήδη στο M3 (`ai-006`, profile 1).

### Profile 2 (10 entries): trade-offs

| Πακέτο | Εφαρμογή | Πηγές | Τι χάνεις ή τι να προσέξεις |
|---|---|---|---|
| `Microsoft.MicrosoftOfficeHub` | Microsoft 365 Copilot (Office hub) | S2, S3 §1, S4 | Την εφαρμογή. Sample S1: `false` |
| `Clipchamp.Clipchamp` | Clipchamp | S2, S3 §1, S4 | Τον video editor. Sample S1: `false` |
| `Microsoft.MicrosoftStickyNotes` | Sticky Notes | S2, S3 §1, S4 | **Δεδομένα χρήστη** (σημειώσεις): βλ. ενότητα 7. Sample S1: `true` |
| `Microsoft.Todos` | Microsoft To Do | S2, S3 §1, S4 | **Δεδομένα χρήστη** (λίστες): βλ. ενότητα 7. Sample S1: `false` |
| `Microsoft.WindowsFeedbackHub` | Feedback Hub | S2, S3 §1, S4 | Την αποστολή feedback μέσω της εφαρμογής. Sample S1: `false` |
| `MSTeams` | Microsoft Teams | S2, S4 | Το Teams (η S1 έχει το αναγνωριστικό `MSTeams`). Η S3 και η S4 έχουν και το `MicrosoftTeams` (S3: «Only removes the personal version (MS Store), does not remove business/enterprise version of teams»), που δεν υπάρχει στην S1 και δεν προτείνεται: βλ. ενότητα 8 |
| `Microsoft.OutlookForWindows` | Outlook for Windows | S2, S3 §3, S4 | Το νέο Outlook. Η S3 το αφαιρεί μόνο με επιλογή |
| `Microsoft.YourPhone` | Phone Link | S3 §2, S4 | Το Phone Link. Η S3 το κρατά από προεπιλογή |
| `MicrosoftCorporationII.MicrosoftFamily` | Family Safety | S3 §1, S4 | Την εφαρμογή Family Safety. Δεν ελέγχθηκε αν οι γονικοί έλεγχοι εξαρτώνται από αυτήν (VM) |
| `MicrosoftCorporationII.QuickAssist` | Quick Assist | S2, S4 | Την απομακρυσμένη βοήθεια. Η Microsoft: «Consider blocking or uninstalling Quick Assist and other remote monitoring and management tools» (S6, πρόταση που συνεχίζεται: «if these tools are not in use in your environment»). Δεν υπάρχει στην S3 |

### Profile 3 (10 entries): deep

| Πακέτο | Εφαρμογή | Πηγές | Τι χάνεις ή τι να προσέξεις |
|---|---|---|---|
| `Microsoft.People` | People | S3 §3, S4 | S3: «Required for & included with Mail & Calendar». Μαζί με το Mail & Calendar |
| `microsoft.windowscommunicationsapps` | Mail & Calendar | S3 §3, S4 | S3: «Mail & Calendar». Η S3 γράφει το όνομα με κεφαλαίο M, η S4 με μικρό (δεν έχει σημασία στο PowerShell) |
| `Microsoft.PowerAutomateDesktop` | Power Automate | S3 §3, S4 | Την εφαρμογή |
| `Microsoft.WindowsMaps` | Maps | S3 §1, S4 | Την εφαρμογή |
| `Microsoft.WindowsAlarms` | Alarms & Clock | S3 §1, S4 | Ξυπνητήρια και χρονόμετρα της εφαρμογής |
| `Microsoft.WindowsSoundRecorder` | Sound Recorder | S2, S3 §1, S4 | Την εφαρμογή |
| `Microsoft.ZuneVideo` | Movies & TV | S3 §1, S4 | Την εφαρμογή |
| `Microsoft.XboxGamingOverlay` | Xbox Game Bar | S3 §3, S4 | S3: «required/useful for some games». Αφαιρεί το Game Bar και μαζί το Gaming Copilot (κατά το Neowin, όπως καταγράφεται στο `ai-009`, ο μόνος τρόπος αφαίρεσης του Gaming Copilot είναι η αφαίρεση του Game Bar). Ρίσκο: medium |
| `Microsoft.XboxGameOverlay` | Xbox Game Overlay | S3 §3, S4 | S3: «required/useful for some games». Ρίσκο: medium |
| `Microsoft.GamingApp` | Xbox | S2, S3 §3, S4 | S3: «required for installing some PC games». Sample S1: `true`. Ρίσκο: medium |

## 5. Για απόφασή σου: δεν τα προτείνω

Η Microsoft τα έχει `true` στο δικό της sample (S1), αλλά ένα Home PC μπορεί να παίζει παιχνίδια και το Store δεν πρέπει να χαλάσει (never-touch).

| Πακέτο | Λόγος που το αποκλείω |
|---|---|
| `Microsoft.Xbox.TCUI` | S3: «UI framework, seems to be required for MS store, photos and certain games» |
| `Microsoft.XboxIdentityProvider` | S3: «Xbox sign-in framework, required for some games» |
| `Microsoft.XboxSpeechToTextOverlay` | S3: «Might be required for some games, WARNING: This app cannot be reinstalled!». Αν δεν επανεγκαθίσταται, το rollback είναι αδύνατο |

Η εναλλακτική είναι να μπουν στο profile 3 με `risk: high`.

## 6. Δεν προσφέρονται ποτέ

- Βασικά εργαλεία: `Microsoft.Windows.Photos`, `Microsoft.WindowsCalculator`, `Microsoft.WindowsCamera`, `Microsoft.WindowsNotepad`, `Microsoft.Paint`, `Microsoft.ScreenSketch` (Snipping Tool), `Microsoft.WindowsTerminal`, `Microsoft.ZuneMusic` (Media Player). Στο sample S1 είναι `false` και η S3 τα κρατά (εκτός Notepad, που δεν υπάρχει στην S3). Τα AI χαρακτηριστικά του Paint καλύπτονται από το `ai-007`.
- `Microsoft.GetHelp`: S3 «Required for some Windows 11 Troubleshooters». Η S4 το αφαιρεί, οι πηγές διαφωνούν, άρα μένει.
- Never-touch: Store, App Installer, Windows Security app. Στις 2026-11-12 προστέθηκε στη λίστα το `Microsoft.SecHealthUI`, που είναι το όνομα του Windows Security στα Windows 11 ([winhelponline](https://www.winhelponline.com/blog/need-new-app-open-windows-defender-link/)): η λίστα είχε μόνο το όνομα των Windows 10. Η αλλαγή μόνο περιορίζει, έχει test, και είναι η μόνη αλλαγή της λίστας σε σχέση με το προηγούμενο πακέτο (ελέγχθηκε με diff).
- Εφαρμογές τρίτων και OEM (Spotify, TikTok, Disney, κ.ά.): η S3 τις γράφει με μερικά ονόματα (π.χ. «Disney», «Netflix») και κατά κανόνα διαφέρουν ανά OEM και περιοχή (υπόθεση). Εκτός v1. Το M2 `ads-003` εμποδίζει τις αθόρυβες εγκαταστάσεις. Πρόταση για αργότερα: attest που μόνο αναφέρει τα μη-Microsoft provisioned πακέτα.
- Παλιά ονόματα της εποχής των Windows 10 (3D Viewer, Print 3D, Skype, Mixed Reality Portal, Wallet κ.ά.) δεν υπάρχουν στη λίστα 25H2 της S1. Το Dev Home έχει διαφορετικό όνομα στην S3 (`Windows.DevHome`) και στην S4 (`Microsoft.Windows.DevHome`) και δεν υπάρχει στην S1: εκτός.

## 7. Παραδοχές για τα entries

- **Δύο βήματα ανά πακέτο:** `Remove-AppxProvisionedPackage` «App packages will not be installed when new user accounts are created» και «Packages will not be removed from existing user accounts»· ο `Remove-AppxPackage` «removes an app package from a user account» και το `-AllUsers` «removes the app package for all user accounts on the computer» και θέλει διαχειριστή (S5). Άρα κάθε entry έχει `action: remove`, `deprovision: true`, `all_users: true`.
- **Δεδομένα εφαρμογής:** η Microsoft Learn περιγράφει μόνο τα `-PreserveRoamableApplicationData` και `-PreserveApplicationData` (το δεύτερο μόνο για εφαρμογές σε ανάπτυξη) και δεν λέει τι γίνεται με τα δεδομένα χωρίς αυτά. Υποθέτουμε ότι τα τοπικά δεδομένα χάνονται, και το plan θα το δείχνει στα Sticky Notes και To Do.
- **Rollback:** `store-reinstall`, `partial`. Η επανεγκατάσταση γίνεται από το Store (App Installer και winget μένουν never-touch). Τα δεδομένα δεν επανέρχονται.
- **Audit:** δύο έλεγχοι ανά entry, όπως στο `ai-006` (εγκατεστημένο και provisioned πλήθος = 0).
- **Εγγραφή:** `tier: T1`, `mode: enforce`, `home_effective: expected` (τα cmdlets δεν εξαρτώνται από την έκδοση), `risk: low` στα profiles 1 και 2, `low` ή `medium` στο 3 όπως στους πίνακες.
- **Μετά από feature update** πακέτα μπορεί να ξαναεγκατασταθούν (ο Geekrewind το αναφέρει για το Copilot). Το `install-drift` τα ξαναελέγχει: το `verify` δείχνει πακέτο που επανήλθε.
- **Η policy `RemoveDefaultMicrosoftStorePackages` δεν χρησιμοποιείται:** η S1 και δύο οδηγοί τη θέλουν μόνο σε Enterprise και Education, ένα σχόλιο στο blog της Microsoft γράφει «There is no plan to release this policy for Win Pro at this time», ενώ ο οδηγός S2 γράφει ότι ισχύει και σε Pro και, με registry και «results may vary», σε Home. Ανεπιβεβαίωτο: η v1 χρησιμοποιεί cmdlets.

## 8. Για έλεγχο σε VM (25H2 και 26H2)

- Ποια από τα 23 πακέτα υπάρχουν στο Home 25H2 και 26H2 (baseline του `docs/VERIFY-PROTOCOL.md`).
- Weather και News: αν επηρεάζονται τα Widgets και το lock screen.
- Family Safety: αν επηρεάζονται οι γονικοί έλεγχοι.
- Sticky Notes και To Do: τι γίνεται με τα δεδομένα στην αφαίρεση και στην επανεγκατάσταση.
- Ξανα-προσθήκη πακέτων μετά από cumulative update ή αναβάθμιση 25H2 σε 26H2.
- Teams: αν υπάρχει και το `MicrosoftTeams` (S3, S4) στο 25H2 και στο 26H2, και τι αφαιρεί σε σχέση με το `MSTeams`.

## 9. Αποφάσεις (πάρθηκαν χωρίς ερώτηση)

1. Διάταξη: 3 / 10 / 10 και επιπλέον 7 παλιά πακέτα στο profile 3: `docs/DECISIONS.md`, D1.
2. Τα τρία πακέτα της ενότητας 5: εκτός: D2.
3. Sticky Notes και To Do: profile 2, με πύλη `-AcceptDataLoss`: D3.
