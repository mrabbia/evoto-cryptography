# eVoto — Specifica tecnica condivisa F1

**Versione:** 0.2  
**Progetto:** Voto elettronico verificabile per elezioni politiche  
**Corso:** Crittografia — LM Sicurezza Informatica, Università degli Studi di Milano  
**Componenti del gruppo:**
- Persona A: Giuseppe Corasaniti
- Persona B: Matteo Rabbia

---

## 1. Scopo del documento

Questo documento costituisce la specifica tecnica condivisa del progetto `evoto`.

Serve a mantenere allineati:

- Persona A;
- Persona B;
- eventuali assistenti AI utilizzati durante lo sviluppo;
- codice, test, tesina e presentazione.

Le decisioni definite qui devono essere considerate il riferimento comune durante F2 e F3.

Non modificare formule, rappresentazioni dei dati o interfacce condivise senza prima concordare la modifica tra Persona A e Persona B.

---

# 2. Obiettivo del progetto

Il progetto implementa una libreria Python per un sistema di voto elettronico verificabile, ispirato all'architettura di ElectionGuard ma riscritto e semplificato.

Il sistema deve dimostrare principalmente:

1. segretezza del voto;
2. verificabilità end-to-end;
3. validità crittografica delle schede;
4. conteggio omomorfico;
5. decifratura a soglia;
6. verificabilità universale tramite un verificatore indipendente.

ElectionGuard è utilizzato solamente come:

- riferimento architetturale;
- riferimento per alcune formule e convenzioni;
- banco di prova per i test incrociati T1-T4.

Il nostro codice non deve dipendere da ElectionGuard in produzione.

---

# 3. Divisione del lavoro

## Persona A — Giuseppe

Responsabilità principali:

- `evoto/gruppo.py`
- `evoto/elgamal.py`
- `evoto/prove.py`
- `evoto/scheda.py`
- `verifica/verifica.py`

Argomenti principali:

- parametri del gruppo;
- hash;
- ElGamal esponenziale;
- operazioni omomorfiche;
- logaritmo discreto limitato;
- prove di Schnorr;
- prove di Chaum-Pedersen;
- prova OR generica;
- Fiat-Shamir;
- regole R1-R5;
- verificatore indipendente.

## Persona B — Matteo

Responsabilità principali:

- `evoto/garanti.py`
- `evoto/decifratura.py`
- `evoto/urna.py`
- `evoto/scrutinio.py`
- `cabina/`
- `notebook/demo_didattica.ipynb`

Argomenti principali:

- Shamir Secret Sharing;
- cerimonia delle chiavi;
- impegni di Feldman;
- gestione delle share;
- decifratura a soglia;
- coefficienti di Lagrange;
- gestione dei garanti assenti;
- bacheca pubblica;
- conteggio;
- scrutinio;
- demo web;
- notebook didattico.

Entrambi devono comunque conoscere e saper spiegare l'intero protocollo.

---

# 4. Dipendenze tra moduli

La dipendenza logica desiderata è:

```text
gruppo.py
    ↓
elgamal.py
    ↓
prove.py
    ↓
scheda.py

gruppo.py
    ↓
elgamal.py
    ↓
prove.py
    ↓
garanti.py
    ↓
decifratura.py
```

I moduli della Persona B possono utilizzare primitive definite dalla Persona A.

Evitare dipendenze inverse o circolari.

In particolare:

- `garanti.py` non deve ridefinire parametri di gruppo;
- `decifratura.py` non deve ridefinire `Ciphertext`;
- `garanti.py` e `decifratura.py` devono utilizzare le primitive condivise di `gruppo.py`, `elgamal.py` e `prove.py`.

---

# 5. Gruppo crittografico

Il sistema lavora in un sottogruppo ciclico di ordine primo `q` di `Z_p*`.

Convenzioni:

```text
p = modulo primo
q = ordine primo del sottogruppo
g = generatore del sottogruppo
```

Devono valere almeno:

```text
q | (p - 1)

g^q ≡ 1 mod p
```

Gli esponenti segreti, i nonce, le challenge e le risposte delle prove vengono trattati modulo `q`.

La configurazione concreta dei parametri sarà responsabilità di:

```text
evoto/gruppo.py
```

Per la demo finale è prevista una configurazione con `p` a 2048 bit e sottogruppo di ordine circa 256 bit.

---

# 6. Tipo condiviso GroupParameters

Rappresentazione prevista:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class GroupParameters:
    p: int
    q: int
    g: int
```

Questa struttura deve essere condivisa tra tutti i moduli.

Non creare copie incompatibili della stessa struttura.

---

# 7. ElGamal esponenziale

La chiave segreta è:

```text
s ∈ Z_q
```

La chiave pubblica è:

```text
K = g^s mod p
```

Per cifrare un valore `v` usando randomness `r`:

```text
Enc_K(v; r) = (alpha, beta)

alpha = g^r mod p

beta = g^v · K^r mod p
```

Il plaintext viene codificato all'esponente.

---

# 8. Tipo condiviso Ciphertext

La rappresentazione canonica di un cifrato sarà:

```python
from dataclasses import dataclass


@dataclass(frozen=True)
class Ciphertext:
    alpha: int
    beta: int
```

Tutto il progetto deve utilizzare questa rappresentazione.

Persona B non deve creare una seconda classe indipendente per rappresentare i cifrati.

---

# 9. Proprietà omomorfica

Se:

```text
C1 = Enc(x; r1)
C2 = Enc(y; r2)
```

allora:

```text
C1 · C2 = Enc(x + y; r1 + r2)
```

ovvero:

```text
(alpha1, beta1) · (alpha2, beta2)
=
(alpha1 · alpha2 mod p,
 beta1 · beta2 mod p)
```

Analogamente:

```text
C1 / C2 = Enc(x - y; r1 - r2)
```

La divisione deve essere implementata tramite inverso modulare.

Queste proprietà permettono di calcolare combinazioni lineari dei voti senza decifrarli.

---

# 10. Regola fondamentale sulla privacy

Una scheda `CAST` individuale non deve essere decifrata.

Il sistema decifra solamente i tally aggregati.

Flusso:

```text
schede cifrate
      ↓
aggregazione omomorfica
      ↓
tally cifrato
      ↓
decifratura a soglia
      ↓
totale
```

---

# 11. Randomness / nonce

Ogni cifratura utilizza:

```text
r ∈ Z_q
```

Nell'uso normale deve essere generato in maniera crittograficamente sicura.

Per i test deve però essere possibile specificarlo esplicitamente.

Interfaccia concettuale:

```python
encrypt(
    message,
    public_key,
    params,
    nonce=None,
)
```

Se:

```text
nonce = None
```

la funzione genera un nonce sicuro.

Se viene passato un valore esplicito, questo viene utilizzato.

Questo è necessario soprattutto per T1, in cui la nostra cifratura deve poter essere confrontata con ElectionGuard usando esattamente gli stessi input.

---

# 12. Hash canonico H

Deve esistere una sola implementazione condivisa dell'hash.

Convenzione prevista:

```text
SHA-256("|x1|x2|...|") mod q
```

Per gli interi viene utilizzata una rappresentazione:

```text
esadecimale
maiuscola
lunghezza pari
```

Esempio concettuale:

```text
H(x1, x2, ..., xn)
```

La funzione deve essere deterministica.

Non implementare copie indipendenti di `H()` nei vari moduli.

La funzione canonica sarà definita in:

```text
evoto/gruppo.py
```

---

# 13. Schnorr

Schnorr dimostra la conoscenza dell'esponente `x` dato:

```text
Y = g^x
```

Protocollo Sigma di base:

```text
r ← Z_q

A = g^r

c = challenge

z = r + c·x mod q
```

Verifica:

```text
g^z = A · Y^c
```

Nel progetto le prove saranno rese non interattive tramite Fiat-Shamir.

Schnorr viene utilizzato in particolare durante la cerimonia delle chiavi.

Nella cerimonia delle chiavi ogni garante allega una prova di Schnorr a ciascun impegno `K_i,j`.

La forma esatta della challenge è fissata nella sezione 36.

---

# 14. Chaum-Pedersen

Chaum-Pedersen dimostra l'uguaglianza di due logaritmi discreti.

Dato:

```text
Y1 = g1^x

Y2 = g2^x
```

si dimostra:

```text
log_g1(Y1) = log_g2(Y2)
```

Una delle applicazioni fondamentali nel progetto riguarda le share di decifratura.

Se il garante `l` possiede la share aggregata `s_l` (sezione 23):

```text
V_l = g^(s_l)

M_l = A^(s_l)
```

deve poter dimostrare:

```text
log_g(V_l) = log_A(M_l)
```

senza rivelare `s_l`.

Per questo la primitiva deve essere generica: le due basi `g1` e `g2` sono parametri qualsiasi del sottogruppo, non sempre la coppia `(g, K)` usata per i cifrati.

La primitiva Chaum-Pedersen sarà implementata da Persona A in:

```text
evoto/prove.py
```

e utilizzata anche dalla Persona B.

---

# 15. Fiat-Shamir

Le prove Sigma interattive vengono rese non interattive calcolando la challenge tramite hash.

Il progetto utilizza una forma forte di Fiat-Shamir.

La challenge deve legare almeno:

```text
contesto / identificativo elezione
enunciato
cifrato quando applicabile
impegni della prova
```

Non è sufficiente calcolare la challenge usando soltanto gli impegni.

Schema concettuale:

```text
c = H(
    election_context,
    statement,
    commitments
)
```

Ogni prova deve essere legata all'enunciato concreto che sta dimostrando.

I contesti `Q` e `Q_bar` e gli input esatti di `H` per ogni prova sono fissati nelle sezioni 35 e 36.

---

# 16. Prova OR generica

Il progetto utilizza una prova generica per dimostrare che un valore cifrato appartiene a:

```text
{0, ..., k}
```

senza rivelare il valore effettivo.

Per:

```text
v ∈ {0, 1, ..., k}
```

la prova contiene `k + 1` rami.

Il ramo corrispondente al valore reale viene costruito onestamente.

Gli altri rami vengono simulati.

Le challenge parziali devono rispettare:

```text
c0 + c1 + ... + ck = c mod q
```

dove `c` è la challenge Fiat-Shamir complessiva.

Non creare una prova completamente diversa per R1, R3, R4 e R5.

La stessa primitiva generica dovrà essere riutilizzata.

Interfaccia concettuale:

```python
prove_value_in_set(
    ciphertext,
    plaintext,
    nonce,
    allowed_values,
    public_key,
    params,
    context,
)
```

e:

```python
verify_value_in_set(
    ciphertext,
    proof,
    allowed_values,
    public_key,
    params,
    context,
)
```

I nomi e i dettagli potranno essere affinati durante F2, ma il principio non deve cambiare senza accordo tra A e B.

Il formato della challenge, compatibile con ElectionGuard nel caso 0/1 (T3), è fissato nella sezione 36.

---

# 17. Regole R1-R5 della scheda

Indichiamo:

```text
l_P = bit relativo alla lista P

p_c = bit relativo alla preferenza per il candidato c

b = bit della scheda bianca
```

## R1 — Ogni casella è un bit

```text
x ∈ {0, 1}
```

Si usa una OR proof a due rami.

---

## R2 — Esattamente una scelta tra liste e bianca

```text
Σ l_P + b = 1
```

Il vincolo viene verificato sul ciphertext ottenuto tramite aggregazione omomorfica.

---

## R3 — Preferenze soltanto nella lista votata

Per ogni candidato `c` appartenente alla lista `P`:

```text
l_P - p_c ∈ {0, 1}
```

Se:

```text
p_c = 1
```

allora deve risultare:

```text
l_P = 1
```

---

## R4 — Massimo tre preferenze

```text
Σ p_c ∈ {0, 1, 2, 3}
```

Si utilizza la prova OR generica con quattro valori ammessi.

---

## R5 — Vincolo di genere

Nel modello iniziale:

```text
Σ p_c ∈ {0, 1, 2}
```

per i candidati appartenenti allo stesso genere.

I dettagli del vincolo devono rimanere parametrizzabili tramite configurazione dell'elezione.

---

# 18. Shamir Secret Sharing

La cerimonia delle chiavi utilizza una soglia:

```text
k-su-n
```

Ogni garante `i` sceglie un proprio polinomio:

```text
P_i(x)
=
a_i,0
+ a_i,1 x
+ ...
+ a_i,k-1 x^(k-1)
mod q
```

Il garante `i` invia al garante `l`:

```text
P_i(l)
```

Il termine costante:

```text
a_i,0
```

rappresenta il contributo segreto del garante.

Il segreto globale concettuale è:

```text
s = Σ a_i,0 mod q
```

ma non deve essere ricostruito o conservato in un singolo punto durante l'esecuzione normale.

Convenzioni fissate nella versione 0.2:

- i garanti sono numerati `1, 2, ..., n`; l'indice `0` non viene mai usato, perché `P_i(0) = a_i,0` è il segreto;
- nel codice la soglia `k` si chiama `quorum`, per non confonderla con il `k` della prova OR e con la chiave `K`;
- deve valere `1 <= quorum <= n`;
- i coefficienti `a_i,j` sono scelti uniformemente in `Z_q` con il modulo `secrets`;
- per i test i coefficienti devono poter essere passati esplicitamente, come il `nonce` di `encrypt` (sezione 11);
- `P_i(l)` viene calcolato modulo `q` con lo schema di Horner;
- le share `P_i(l)` sono private: non vanno mai nel registro pubblico.

Nel progetto i garanti sono simulati in un unico programma, quindi le share passano in memoria. In un sistema reale viaggerebbero su un canale cifrato e autenticato: la semplificazione va dichiarata nella tesina.

---

# 19. Impegni di Feldman

Per ogni coefficiente:

```text
a_i,j
```

il garante pubblica:

```text
K_i,j = g^(a_i,j)
```

Una share ricevuta dal garante `l` può essere verificata tramite:

```text
g^(P_i(l))
=
∏ K_i,j^(l^j)
```

Questo permette di controllare la coerenza della share con il polinomio dichiarato.

Ogni impegno `K_i,j` è accompagnato da una prova di Schnorr che dimostra la conoscenza di `a_i,j` (sezione 36).

Il garante `l` accetta la share `P_i(l)` solo se:

- ogni `K_i,j` appartiene al sottogruppo di ordine `q`;
- ogni prova di Schnorr del garante `i` è valida;
- vale l'uguaglianza di Feldman scritta sopra.

Se un controllo fallisce, la cerimonia si interrompe con un `ValueError` che indica il garante `i`.

Non implementiamo una fase di reclamo: anche questa semplificazione va dichiarata nella tesina.

Persona B implementerà questa logica in:

```text
evoto/garanti.py
```

---

# 20. Chiave pubblica congiunta

La chiave pubblica dell'elezione viene ottenuta dai commitment relativi ai termini costanti:

```text
K = ∏ K_i,0
```

Poiché:

```text
K_i,0 = g^(a_i,0)
```

si ottiene:

```text
K = g^(Σ a_i,0)
```

La chiave risultante deve essere direttamente utilizzabile da:

```text
evoto/elgamal.py
```

senza conversioni o rappresentazioni alternative.

Decisione v0.2: la chiave pubblica è un semplice `int`.

Oltre a `K`, al termine della cerimonia ogni garante ottiene la propria share aggregata `s_l` (sezione 23).

---

# 21. Lagrange

Per ricostruire informazioni a soglia vengono utilizzati coefficienti di Lagrange.

Dato un insieme `S` di indici disponibili, il coefficiente relativo a `i`, valutato in zero, è concettualmente:

```text
λ_i =
∏ (-j) / (i-j) mod q
```

per:

```text
j ∈ S
j ≠ i
```

Le divisioni devono essere implementate tramite inverso modulare modulo `q`.

La funzione per il calcolo dei coefficienti deve essere isolata e direttamente testabile.

Nel progetto `S` è l'insieme dei garanti presenti alla decifratura, con `|S| >= quorum`.

La funzione sarà definita in:

```text
evoto/decifratura.py
```

e controlla che gli indici di `S` siano positivi e distinti e che `i` appartenga a `S`.

---

# 22. Conteggio omomorfico

Per ogni casella o candidato, i ciphertext delle schede CAST vengono moltiplicati.

Se:

```text
C_j = (alpha_j, beta_j)
```

allora:

```text
A = ∏ alpha_j mod p

B = ∏ beta_j mod p
```

e:

```text
(A, B) = Enc(Σ v_j)
```

Il risultato è quindi un tally cifrato.

---

# 23. Decifratura del tally

Decisione v0.2: il progetto usa il modello a **share aggregate**, lo stesso dell'esempio numerico della proposta di progetto.

Il modello di ElectionGuard, con share compensate per i garanti assenti, non viene implementato: la differenza va dichiarata nel capitolo 6 della tesina.

## Share aggregata di ogni garante

Al termine della cerimonia il garante `l` somma le share ricevute da tutti i garanti, compresa la propria:

```text
s_l = Σ_i P_i(l) mod q
```

Se chiamiamo:

```text
S(x) = Σ_i P_i(x) mod q
```

allora `S` ha grado `k - 1`, `S(0) = s` e `s_l = S(l)`.

Quindi `s_l` è una share di Shamir del segreto globale `s`, senza che nessuno abbia mai conosciuto `s`.

La chiave di verifica del garante `l` è:

```text
V_l = g^(s_l) = ∏_i ∏_j K_i,j^(l^j) mod p
```

Chiunque può calcolarla dagli impegni pubblici di Feldman.

## Share di decifratura

Dato il tally cifrato:

```text
(A, B)
```

e l'insieme `S` dei garanti presenti, con `|S| >= quorum`, ogni garante `l ∈ S` pubblica:

```text
M_l = A^(s_l) mod p
```

accompagnato da una prova Chaum-Pedersen che dimostra:

```text
log_g(V_l) = log_A(M_l)
```

## Combinazione delle share

Chiunque calcola i coefficienti di Lagrange `λ_l` su `S` (sezione 21) e:

```text
M = ∏_{l ∈ S} M_l^(λ_l) mod p
```

Poiché:

```text
Σ_{l ∈ S} λ_l · s_l = S(0) = s mod q
```

si ottiene:

```text
M = A^s = K^R
```

dove `R` è la somma delle randomness delle schede aggregate.

Infine:

```text
B / M = g^t
```

dove:

```text
t = totale dei voti
```

Il valore ottenuto non è direttamente `t`, ma `g^t`.

## Garanti assenti

Un garante assente semplicemente non compare in `S`: bastano `quorum` garanti qualsiasi e il risultato non cambia.

Se i garanti presenti sono meno di `quorum`, la decifratura si interrompe con un `ValueError`.

## Controlli del verificatore (V6 e V7)

Il verificatore ricalcola dal registro:

- `V_l` di ogni garante presente, a partire dagli impegni di Feldman;
- la validità di ogni prova Chaum-Pedersen;
- l'appartenenza al sottogruppo di ogni `M_l`;
- i coefficienti `λ_l` e il valore `M`;
- l'uguaglianza `B / M = g^t` con il totale pubblicato.

---

# 24. Logaritmo discreto limitato

Per ricavare:

```text
t
```

da:

```text
g^t
```

si utilizzerà un algoritmo di logaritmo discreto limitato.

La soluzione prevista è:

```text
baby-step giant-step
```

L'algoritmo è praticabile perché il plaintext rappresenta un conteggio elettorale e quindi appartiene a un intervallo limitato.

La relativa implementazione sarà responsabilità di Persona A in:

```text
evoto/elgamal.py
```

---

# 25. Sei fasi del protocollo

## Fase 1 — Cerimonia delle chiavi

```text
garanti
→ polinomi
→ commitment
→ share
→ verifiche
→ chiave pubblica congiunta
```

---

## Fase 2 — Voto

Ogni casella della scheda viene cifrata con ElGamal esponenziale.

Alla scheda vengono associate le prove necessarie per R1-R5.

---

## Fase 3 — Bacheca pubblica

Le schede cifrate e le informazioni verificabili vengono pubblicate nel registro.

Sono previsti:

```text
codici di tracciamento
catena di hash
cast-or-spoil
```

---

## Fase 4 — Conteggio omomorfico

Le schede CAST valide vengono aggregate senza essere decifrate.

---

## Fase 5 — Decifratura a soglia

Soltanto i tally aggregati vengono decifrati.

Sono necessari almeno `k` garanti su `n`.

---

## Fase 6 — Verifica e scrutinio

Il verificatore indipendente deve poter ricontrollare dal registro pubblico:

```text
V1 parametri
V2 chiavi dei garanti
V3 prove delle schede
V4 catena dei codici
V5 aggregazione
V6 prove di decifratura e Lagrange
V7 totali
V8 scrutinio, seggi ed eletti
```

---

# 26. Test incrociati con ElectionGuard

ElectionGuard si trova localmente in:

```text
riferimento/
```

ed è escluso dal repository tramite `.gitignore`.

I test previsti sono:

## T1 — ElGamal

Stessa:

```text
chiave pubblica
plaintext
randomness
```

deve permettere di confrontare i nostri ciphertext con quelli di ElectionGuard.

---

## T2 — Hash

La nostra funzione `H` deve essere confrontabile sugli stessi input con la convenzione ElectionGuard scelta dal progetto.

Attenzione: `hash_elems` di ElectionGuard 1.4 serializza in esadecimale solo `ElementModP` ed `ElementModQ`; gli `int` Python vengono serializzati in decimale.

Nel test incrociato gli interi vanno quindi passati a ElectionGuard come `ElementModP` o `ElementModQ`.

---

## T3 — Prove 0/1

Verificare la compatibilità o comunque la correttezza incrociata delle prove 0/1 secondo le convenzioni fissate.

---

## T4 — Elezione completa

Dati gli stessi voti:

```text
totali della nostra implementazione
=
totali ElectionGuard
=
conteggio in chiaro
```

---

# 27. Tipi condivisi previsti

Tipi minimi attualmente concordati:

```python
@dataclass(frozen=True)
class GroupParameters:
    p: int
    q: int
    g: int


@dataclass(frozen=True)
class Ciphertext:
    alpha: int
    beta: int
```

Decisione v0.2: la chiave pubblica è un semplice `int` (sezione 20), quindi il tipo `PublicKey` non viene creato.

Tipi proposti nella versione 0.2, con campi da confermare nella review:

```python
# evoto/prove.py (Persona A)

@dataclass(frozen=True)
class SchnorrProof:
    commitment: int      # h = g^u
    challenge: int       # c
    response: int        # z = u + c·x mod q


@dataclass(frozen=True)
class ChaumPedersenProof:
    commitment_1: int    # a = g1^u
    commitment_2: int    # b = g2^u
    challenge: int       # c
    response: int        # z = u + c·x mod q


# evoto/garanti.py (Persona B)

@dataclass(frozen=True)
class GuardianRecord:
    index: int                          # l, da 1 a n
    commitments: tuple[int, ...]        # K_l,0 ... K_l,k-1
    proofs: tuple[SchnorrProof, ...]    # una prova per impegno


# evoto/decifratura.py (Persona B)

@dataclass(frozen=True)
class DecryptionShare:
    guardian_index: int                 # l
    partial_decryption: int             # M_l = A^(s_l)
    proof: ChaumPedersenProof
```

`GuardianRecord` e `DecryptionShare` contengono solo dati pubblici e finiscono nel registro.

Il tipo `Guardian`, che contiene coefficienti, share ricevute e share aggregata, è privato del garante: la sua struttura interna è libera e non viene mai pubblicata.

Resta previsto `ValueSetProof` per la prova OR (Persona A).

Quando uno di questi tipi diventa dipendenza tra Persona A e Persona B, la sua struttura deve essere concordata prima del merge.

---

# 28. Regole per lo sviluppo in parallelo

Persona A e Persona B lavorano su branch separati.

`main` deve restare stabile.

Flusso standard:

```text
main aggiornato
      ↓
nuovo branch
      ↓
implementazione
      ↓
test
      ↓
push
      ↓
Pull Request
      ↓
review dell'altro componente
      ↓
merge
```

Non lavorare direttamente su `main`.

Prima di iniziare un nuovo branch:

```bash
git switch main
git pull
```

Poi:

```bash
git switch -c <nome-branch>
```

---

# 29. Convenzioni per i branch

Esempi:

```text
feature/group-parameters
feature/elgamal
feature/zkp
feature/guardians
feature/threshold-decryption
feature/ballot
feature/ballot-box
feature/verifier
feature/scrutiny
feature/booth

docs/f1-specification
docs/thesis
docs/presentation
```

---

# 30. Ambiente condiviso

Versione Python:

```text
Python 3.12
```

Gestione ambiente:

```text
uv
```

Dipendenze iniziali:

```text
gmpy2
pytest
```

File di ambiente versionati:

```text
.python-version
pyproject.toml
uv.lock
```

Il virtual environment:

```text
.venv/
```

non viene versionato.

Per sincronizzare un ambiente dopo un pull:

```bash
uv sync
```

Su Windows:

```powershell
.venv\Scripts\Activate.ps1
```

Su macOS:

```bash
source .venv/bin/activate
```

---

# 31. Regole per gli assistenti AI

Gli assistenti AI utilizzati da Persona A o Persona B devono rispettare questa specifica.

In particolare:

1. non modificare autonomamente formule crittografiche già concordate;
2. non creare strutture duplicate incompatibili;
3. non modificare API condivise senza evidenziarlo esplicitamente;
4. non introdurre dipendenze esterne senza motivazione;
5. non sostituire primitive implementate da noi con librerie che nascondano il funzionamento richiesto dal progetto;
6. ElectionGuard è un riferimento, non una dipendenza della nostra libreria;
7. ogni funzione crittografica importante deve avere test;
8. il codice deve essere comprensibile e spiegabile oralmente;
9. privilegiare implementazioni semplici e didattiche rispetto a ottimizzazioni premature;
10. segnalare sempre quando una proposta è una scelta progettuale nuova e non una decisione già contenuta in questa specifica.

Quando un assistente AI riceve questo documento in una nuova conversazione deve considerarlo come stato corrente del progetto.

---

# 32. Stato al termine di F0

F0 è completata.

Sono disponibili:

```text
repository GitHub privato condiviso
Python 3.12
uv
virtual environment
gmpy2
pytest
test di setup
ElectionGuard come riferimento separato
workflow branch + Pull Request verificato
```

I test iniziali risultano:

```text
2 passed
```

sia su Windows sia su macOS.

ElectionGuard è conservato localmente in:

```text
riferimento/
```

e possiede un ambiente separato.

---

# 33. Criteri di completamento F1

F1 è considerata completata quando entrambi i componenti sanno spiegare:

```text
ElGamal esponenziale
omomorfismo
Schnorr
Chaum-Pedersen
Fiat-Shamir
OR proof
regole R1-R5
Shamir
Feldman
Lagrange
chiave pubblica congiunta
conteggio omomorfico
decifratura a soglia
sei fasi del protocollo
```

e quando questa specifica è stata revisionata e mergiata in `main`.

---

# 34. Passo successivo

Dopo il completamento di F1:

## Persona A

`feature/group-parameters` (`evoto/gruppo.py`) è completato.

Ordine proposto per il resto di F2, in modo che Persona B possa proseguire F3:

```text
1. evoto/elgamal.py    Ciphertext, encrypt, operazioni omomorfiche, logaritmo discreto
2. evoto/prove.py      Schnorr e Chaum-Pedersen generico
3. evoto/prove.py      prova OR generica
```

con relativi test T1-T3.

## Persona B

inizia F3 concentrandosi su:

```text
evoto/garanti.py
evoto/decifratura.py
```

con:

```text
Shamir
Feldman
share verificabili
Lagrange
decifratura a soglia
```

Persona B deve utilizzare le interfacce condivise implementate dalla Persona A e non duplicarle.

Le parti che dipendono solo da `gruppo.py` (polinomi, impegni di Feldman, share aggregate, coefficienti di Lagrange) possono partire subito.

Prove di Schnorr, share di decifratura e test del referendum seguono il merge di `elgamal.py` e `prove.py`.

Obiettivo congiunto di F2 + F3:

```text
referendum sì/no end-to-end
```

realizzato interamente con la nostra libreria e verificato tramite test.

---

# 35. Contesti di hash Q e Q_bar

Decisione v0.2.

Ogni prova viene legata all'elezione tramite due valori di contesto.

## Hash di base Q

Serve durante la cerimonia delle chiavi, quando la chiave congiunta non esiste ancora:

```text
Q = H(p, q, g, n, k, e)
```

dove:

```text
n = numero di garanti
k = quorum
e = identificativo intero dell'elezione
```

Nei test si usa `e = 1`.

Quando esisterà `config/elezione_esempio.json`, `e` sarà l'hash della configurazione, con una funzione da fissare insieme a `registro.py`.

## Hash esteso Q_bar

Serve dopo la cerimonia, per le prove delle schede e per le prove di decifratura:

```text
Q_bar = H(Q, K)
```

Entrambi i valori sono calcolati da funzioni definite in:

```text
evoto/garanti.py
```

Le altre funzioni ricevono `Q` o `Q_bar` come parametro `context`, senza ricalcolarli.

---

# 36. Fiat-Shamir: input esatti di H per ogni prova

Decisione v0.2.

Il verificatore non importa `evoto`, quindi questa sezione è l'unico accordo tra chi produce le prove e chi le controlla.

Regola generale: nella challenge entrano, in quest'ordine,

1. il contesto (`Q` oppure `Q_bar`) e gli indici che identificano la prova;
2. tutte le basi e tutti i valori pubblici dell'enunciato;
3. gli impegni della prova.

| Prova | Enunciato | Challenge |
|---|---|---|
| Schnorr sull'impegno `K_i,j` | conosco `a_i,j` con `K_i,j = g^(a_i,j)` | `c = H(Q, i, j, g, K_i,j, h)` |
| Chaum-Pedersen della share di decifratura | `log_g(V_l) = log_A(M_l)` | `c = H(Q_bar, l, g, V_l, A, M_l, a, b)` |
| Prova OR su `{0, ..., k}` (R1, R3, R4, R5) | `(alpha, beta)` cifra un valore in `{0, ..., k}` | `c = H(Q_bar, alpha, beta, a_0, b_0, ..., a_k, b_k)` |

Per la prova OR con `k = 1` il formato coincide con quello di ElectionGuard: è la condizione per il test T3.

Per questo la prova OR non segue alla lettera la regola generale; `g` e `K` sono comunque legati tramite `Q_bar`.

Per R2 si usa la stessa prova OR con il solo valore ammesso `1`, quindi `c = H(Q_bar, alpha, beta, a, b)`.

## Schnorr

Dati `Y = g^x` e un nonce `u ∈ Z_q`:

```text
h = g^u mod p

c = H(context, g, Y, h)

z = u + c·x mod q
```

Verifica:

```text
Y e h appartengono al sottogruppo

c = H(context, g, Y, h)

g^z = h · Y^c mod p
```

Per l'impegno `K_i,j` della cerimonia delle chiavi il contesto è `(Q, i, j)`.

## Chaum-Pedersen generico

Dati `Y1 = g1^x`, `Y2 = g2^x` e un nonce `u ∈ Z_q`:

```text
a = g1^u mod p

b = g2^u mod p

c = H(context, g1, Y1, g2, Y2, a, b)

z = u + c·x mod q
```

Verifica:

```text
Y1, Y2, a e b appartengono al sottogruppo

c = H(context, g1, Y1, g2, Y2, a, b)

g1^z = a · Y1^c mod p

g2^z = b · Y2^c mod p
```

Per la share di decifratura: contesto `(Q_bar, l)`, `g1 = g`, `Y1 = V_l`, `g2 = A`, `Y2 = M_l`, `x = s_l`.

Come per `encrypt`, il nonce `u` è generato con `secrets` ma deve poter essere passato esplicitamente nei test.

## Differenze rispetto a ElectionGuard 1.4

- Schnorr: ElectionGuard usa `c = H(K_i,j, h)`; noi aggiungiamo contesto e indici.
- Share di decifratura: ElectionGuard usa `c = H(Q_bar, A, B, a, b, M)`; noi aggiungiamo l'indice del garante e la chiave di verifica `V_l`, che fa parte dell'enunciato.

È la forma forte di Fiat-Shamir richiesta dalla sezione 15.

---

# 37. Convenzioni e responsabilità aggiuntive

Decisioni v0.2.

## Controlli sugli elementi ricevuti

Ogni elemento del gruppo ricevuto da un altro partecipante o letto dal registro (impegni, chiavi di verifica, share di decifratura, impegni delle prove, cifrati) deve superare `is_subgroup_element` prima di essere usato.

È necessario perché il gruppo RFC 5114 a 2048 bit previsto per la demo non è un safe prime: `(p - 1) / q` è composto (è almeno pari) e senza questo controllo sono possibili attacchi a sottogruppi piccoli.

Challenge, risposte e share devono essere interi compresi tra `0` e `q - 1`.

## Gruppo didattico per i test

Il gruppo `p = 2579`, `q = 1289`, `g = 4` va definito una sola volta, come costante `TEST_PARAMS` in `evoto/gruppo.py` (Persona A).

Fino ad allora ogni file di test lo definisce localmente con gli stessi valori.

## Responsabilità

| Cosa | Dove | Chi |
|---|---|---|
| Prodotto e divisione di due cifrati | `evoto/elgamal.py` | A |
| Logaritmo discreto baby-step giant-step | `evoto/elgamal.py` | A |
| Contesti `Q` e `Q_bar` | `evoto/garanti.py` | B |
| Coefficienti di Lagrange | `evoto/decifratura.py` | B |
| Aggregazione dei cifrati di più schede (tally) | `evoto/urna.py` | B |
| Test d'integrazione del referendum sì/no | `test/test_referendum.py` | B, con review di A |

## Nota per la tesina

La generazione congiunta della chiave con impegni di Feldman, la stessa usata da ElectionGuard, permette a un garante disonesto di influenzare in parte la distribuzione della chiave pubblica (Gennaro, Jarecki, Krawczyk, Rabin, 1999).

Nel modello honest-but-curious che adottiamo non è un problema, ma va citato nell'analisi critica.

---

# 38. Esempio numerico di riferimento per i test

Gruppo didattico: `p = 2579`, `q = 1289`, `g = 4`.

Tre garanti, `quorum = 2`, identificativo dell'elezione `e = 1`.

I polinomi sono scelti in modo che la loro somma coincida con il polinomio dell'esempio della proposta di progetto:

```text
P_1(x) = 300 + 40x
P_2(x) = 400 + 50x
P_3(x) =  65 + 10x

S(x)   = 765 + 100x
```

## Cerimonia delle chiavi

| Valore | Garante 1 | Garante 2 | Garante 3 |
|---|---|---|---|
| `K_i,0` | 2228 | 523 | 299 |
| `K_i,1` | 1370 | 2277 | 1502 |
| `P_i(1)` | 340 | 450 | 75 |
| `P_i(2)` | 380 | 500 | 85 |
| `P_i(3)` | 420 | 550 | 95 |

| Garante `l` | Share aggregata `s_l` | Chiave di verifica `V_l` |
|---|---|---|
| 1 | 865 | 2502 |
| 2 | 965 | 2488 |
| 3 | 1065 | 2237 |

```text
K     = 2228 · 523 · 299 mod 2579 = 530
Q     = H(2579, 1289, 4, 3, 2, 1) = 889
Q_bar = H(889, 530)               = 744
```

## Voti e tally

Voti `1, 0, 1` con randomness `11, 22, 33`:

```text
(850, 2375)   (380, 22)   (625, 670)

(A, B) = (1196, 154)
```

## Decifratura

```text
M_1 = 1196^865  mod 2579 = 60
M_2 = 1196^965  mod 2579 = 508
M_3 = 1196^1065 mod 2579 = 1894
```

| Garanti presenti `S` | Coefficienti `λ_l` | `M` |
|---|---|---|
| {1, 3} | 646, 644 | 332 |
| {1, 2} | 2, 1288 | 332 |
| {2, 3} | 3, 1287 | 332 |
| {1, 2, 3} | 3, 1286, 1 | 332 |

In ogni caso `B / M = 154 / 332 = 16 = 4^2`, quindi `t = 2`.

## Prove con nonce fissato

Schnorr del garante 1 sull'impegno `K_1,0` (`x = 300`), con `u = 7`:

```text
h = 910    c = H(889, 1, 0, 4, 2228, 910) = 957    z = 949
```

Chaum-Pedersen del garante 1 sulla share `M_1` (`x = 865`), con `u = 7`:

```text
a = 910    b = 1033    c = H(744, 1, 4, 2502, 1196, 60, 910, 1033) = 524    z = 828
```

---

# 39. Storico delle versioni

| Versione | Contenuto |
|---|---|
| 0.1 | Specifica condivisa di F1 |
| 0.2 | Decisioni per F3: modello a share aggregate (sezione 23), contesti e input di Fiat-Shamir (sezioni 35 e 36), tipi condivisi e chiave pubblica come `int` (sezioni 20 e 27), convenzioni su garanti e controlli (sezioni 18, 19 e 37), nota su T2 (sezione 26), esempio numerico (sezione 38) |
