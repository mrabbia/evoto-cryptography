# eVoto — Specifica tecnica condivisa F1

**Versione:** 0.6  
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
r ∈ {1, ..., q - 1}
```
Il valore r = 0 non viene utilizzato, perché produrrebbe alpha = 1
e renderebbe la cifratura deterministica rispetto al messaggio.

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

Aggiornamento v0.3: `prove_value_in_set` accetta un nonce compreso tra `0` e `q - 1`. Serve per i cifrati derivati delle regole R2-R5, la cui randomness è una somma o una differenza di nonce modulo `q` e può valere `0`. `encrypt` continua invece a richiedere un nonce tra `1` e `q - 1` per ogni cifratura nuova.

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

Aggiornamento v0.3: `ValueSetProof` è implementato in `prove.py`. La cerimonia simulata restituisce il tipo `KeyCeremony` (`garanti.py`), che contiene i dati pubblici della cerimonia e, solo perché i garanti sono simulati in un unico programma, le loro share segrete. I tipi della scheda politica sono descritti nella sezione 40, quelli della bacheca e dello spoglio nelle sezioni 43, 44 e 45.

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
merge

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

Sezione storica, scritta al termine di F1. Lo stato aggiornato del progetto è nella sezione 48.

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

Decisione v0.3: `e` coincide con il campo `election_id` della configurazione
ufficiale dell'elezione (sezione 42).

Di conseguenza:

Q = H(p, q, g, n, k, election_id)

Non viene calcolato un secondo hash della configurazione per ricavare `e`.
La configurazione completa viene comunque pubblicata nel registro e verificata
dal verificatore indipendente.

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

# 39. Aggiornamento v0.3

Le sezioni 40-48 documentano il lavoro successivo a F3:

- sezione 40: la scheda politica di F4 (Persona A);
- sezione 41: il nucleo del verificatore indipendente (Persona A);
- sezioni 42-46: F5 (Persona B), cioè configurazione, voto, bacheca, spoglio e scrutinio;
- sezione 47: i dati pubblici che il registro deve contenere;
- sezione 48: lo stato del progetto.

Il verificatore non importa `evoto`: le formule e gli ordini scritti qui sono l'unico riferimento comune tra chi produce i dati e chi li controlla.

---

# 40. Scheda politica (F4)

Modulo: `evoto/scheda.py` (Persona A).

## Tipi

```python
@dataclass(frozen=True)
class PreferenceMetadata:
    list_index: int      # lista a cui appartiene la casella
    gender: str          # genere usato da R5


@dataclass(frozen=True)
class BallotLayout:
    list_count: int
    preference_metadata: tuple[PreferenceMetadata, ...]


@dataclass(frozen=True)
class EncryptedBallot:
    list_ciphertexts: tuple[Ciphertext, ...]
    blank_ciphertext: Ciphertext
    preference_ciphertexts: tuple[Ciphertext, ...]


@dataclass(frozen=True)
class BallotWitness:          # privato del votante
    list_plaintexts: tuple[int, ...]
    blank_plaintext: int
    preference_plaintexts: tuple[int, ...]
    list_nonces: tuple[int, ...]
    blank_nonce: int
    preference_nonces: tuple[int, ...]


@dataclass(frozen=True)
class BallotProofs:
    r1_proofs: tuple[ValueSetProof, ...]
    r2_proof: ValueSetProof
    r3_proofs: tuple[ValueSetProof, ...]
    r4_proof: ValueSetProof
    r5_proofs: tuple[ValueSetProof, ...]
```

`BallotLayout` viene dalla configurazione ufficiale (sezione 42): i metadati delle preferenze non sono mai scelti dal votante.

## Ordine canonico

I cifrati di una scheda seguono sempre quest'ordine:

```text
liste (indice 0, ..., L - 1), scheda bianca, preferenze (ordine del layout)
```

È l'ordine di `EncryptedBallot.all_ciphertexts()` e vale anche per il witness, l'impronta della scheda (sezione 43) e i totali di una circoscrizione (sezione 45).

## Prove

Tutte le prove sono prove OR (sezione 16) con contesto `Q_bar`:

| Prove | Cifrato su cui si dimostra | Valori ammessi |
|---|---|---|
| `r1_proofs[k]` | k-esimo cifrato in ordine canonico | `(0, 1)` |
| `r2_proof` | prodotto dei cifrati delle liste e della scheda bianca | `(1,)` |
| `r3_proofs[k]` | `lista[metadata[k].list_index] / preferenza[k]` | `(0, 1)` |
| `r4_proof` | prodotto di tutte le preferenze | `(0, ..., max_preferences)` |
| `r5_proofs[g]` | prodotto delle preferenze del gruppo di genere `g` | `(0, ..., max_preferences_per_gender)` |

I gruppi di genere seguono l'ordine della prima comparsa di ciascun genere nel layout.

La randomness di un cifrato derivato è la somma (o la differenza, per R3) dei nonce modulo `q` e può valere `0` (sezione 16).

## Limiti delle preferenze

`BallotLayout` contiene i campi pubblici:

- `max_preferences`;
- `max_preferences_per_gender`.

I valori sono ricavati dalla configurazione ufficiale dell'elezione tramite `build_ballot_layout`.

R4 costruisce dinamicamente l'insieme dei valori ammessi:

```text
(0, ..., max_preferences)

---

# 41. Verificatore indipendente (nucleo)

Modulo: `verifica/verifica.py` (Persona A).

Il verificatore usa solo la libreria standard di Python e `gmpy2` e non importa `evoto`. Alcune formule di `garanti.py`, `decifratura.py` e `prove.py` sono quindi riscritte di proposito.

Convenzioni sui dati:

```text
cifrato:           (alpha, beta)
ramo di prova OR:  (commitment_1, commitment_2, challenge, response)
```

Controlli già implementati:

```text
V1 parametri del gruppo e chiave pubblica
V2 prove di Schnorr sugli impegni e chiave pubblica congiunta
V3 prove OR e regole R2-R5 sui cifrati derivati
V6 prove Chaum-Pedersen delle share, chiavi di verifica V_l, Lagrange, combinazione
```

Controlli che dipendono da F5 e dal formato del registro:

```text
V4 catena dei codici di tracciamento        sezione 44
V5 aggregazione delle schede CAST           sezione 45
V7 totali decifrati                         sezione 45
V8 scrutinio, seggi ed eletti               sezione 46
parser del registro e orchestrazione V1-V8  sezione 47
```

---

# 42. Configurazione dell'elezione

Modulo: `evoto/configurazione.py` (Persona B).
File di esempio: `config/elezione_esempio.json`.

Cambiare legge elettorale significa cambiare questo file, non il codice.

## Formato

```json
{
  "name": "Elezione politica di esempio",
  "election_id": 1,
  "seats": 30,
  "rules": {
    "max_preferences": 3,
    "max_preferences_per_gender": 2,
    "list_threshold_percent": 3,
    "coalition_threshold_percent": 10,
    "bonus_threshold_percent": 42,
    "bonus_seats_percent": 55
  },
  "lists": [
    {"name": "Lista A", "coalition": "Coalizione Alfa"},
    {"name": "Lista C", "coalition": null}
  ],
  "districts": [
    {
      "name": "Nord",
      "candidates": {
        "Lista A": [
          {"name": "Ferri A.", "gender": "M"},
          {"name": "Galli M.", "gender": "M"}
        ],
        "Lista C": [
          {"name": "Moretti V.", "gender": "M"}
        ]
      }
    }
  ]
}
```

Regole:

- l'indice di una lista è la sua posizione in `lists`;
- le coalizioni sono ricavate dal campo `coalition`, nell'ordine della prima comparsa; `null` indica una lista non coalizzata;
- ogni circoscrizione ha candidati per tutte e sole le liste;
- il primo candidato di ogni lista è il capolista bloccato, senza casella di preferenza; ogni altro candidato ha una casella;
- le percentuali sono convertite in frazioni esatte (`2.5` diventa `1/40`), senza arrotondamenti in virgola mobile;
- `election_id` è l'identificativo `e` del contesto `Q` (sezione 35).

## Caselle di preferenza e layout

L'ordine delle caselle di preferenza di una circoscrizione è: lista dopo lista, nell'ordine di `lists`, e dentro ogni lista i candidati dalla posizione 1 in poi. La casella `k` corrisponde quindi alla coppia `(indice della lista, posizione del candidato)` restituita da `preference_candidates`.

`build_ballot_layout` costruisce il `BallotLayout` della circoscrizione con lo stesso ordine e il genere di ogni candidato.

`build_ballot_layout` copia nel `BallotLayout` i valori
`max_preferences` e `max_preferences_per_gender` definiti nella configurazione.

Le prove R4 e R5 e il verificatore indipendente usano quindi direttamente i limiti configurati, senza valori fissi nel codice.

## Configurazione di esempio

Tre circoscrizioni (Nord, Centro, Sud), 30 seggi, otto liste: la Coalizione Alfa (liste A, B, D), la Coalizione Beta (liste E, F, G) e due liste singole (C, H). Ogni lista ha il capolista e quattro candidati in ogni circoscrizione. Nella circoscrizione Nord le liste A, B e C riprendono l'esempio della proposta di progetto. Nomi e liste sono inventati.

Le soglie e il premio sono valori illustrativi, da allineare al testo definitivo della legge.

---

# 43. Voto e sfida di Benaloh

Modulo: `evoto/voto.py` (Persona B), la logica del dispositivo di voto.

## Scelta dell'elettore

```python
@dataclass(frozen=True)
class VoterChoice:
    list_index: int | None           # None: nessuna lista segnata
    preferences: tuple[int, ...]     # caselle di preferenza segnate
```

Il dispositivo traduce la scelta nei bit delle caselle:

- lista segnata: bit 1 sulla lista, 0 sulle altre e sulla scheda bianca;
- nessuna lista ma preferenze tutte della stessa lista: la lista viene segnata, perché una preferenza vale anche per la sua lista;
- nessuna lista e nessuna preferenza: scheda bianca;
- nessuna lista e preferenze in liste diverse: scelta rifiutata.

Il dispositivo controlla solo la forma della scelta. Il rispetto di R3, R4 ed R5 è garantito dalle prove: una scelta che le viola non produce una scheda (`prove_value_in_set` fallisce).

Ogni casella viene cifrata con un nonce fresco tra `1` e `q - 1`.

## Impronta della scheda

```text
h = H(Q_bar, d, alpha_1, beta_1, ..., alpha_m, beta_m)
```

dove `d` è l'indice della circoscrizione e i cifrati seguono l'ordine canonico (sezione 40).

## Sfida di Benaloh (cast-or-spoil)

1. Il dispositivo cifra la scheda, costruisce le prove e mostra l'impronta `h`.
2. L'elettore sceglie se depositare la scheda (CAST) o sprecarla (SPOILED).
3. Una scheda sprecata viene pubblicata insieme al witness (voti e nonce): chiunque la ricifra e controlla che i cifrati coincidano.
4. Dopo una scheda sprecata l'elettore prepara una nuova scheda, con nonce nuovi.

Il dispositivo non sa in anticipo quali schede verranno controllate, quindi non può barare senza rischiare di essere scoperto.

Scelta di progetto: la scheda sprecata si apre rivelando i nonce, come in Helios, e non con una decifratura dei garanti come in ElectionGuard. Così resta vera la regola della sezione 10: i garanti non decifrano mai una singola scheda.

---

# 44. Bacheca pubblica

Modulo: `evoto/urna.py` (Persona B).

## Righe della bacheca

```python
@dataclass(frozen=True)
class BoardEntry:
    sequence: int                          # posizione, da 1
    district_index: int
    state: str                             # "CAST" oppure "SPOILED"
    ballot: EncryptedBallot
    proofs: BallotProofs
    ballot_hash: int                       # impronta, sezione 43
    tracking_code: int
    revealed_witness: BallotWitness | None # solo per SPOILED


@dataclass(frozen=True)
class BulletinBoard:
    extended_base_hash: int                # Q_bar
    genesis_code: int
    entries: tuple[BoardEntry, ...]
```

La bacheca è a sola aggiunta: ogni deposito restituisce una nuova bacheca con una riga in più.

## Catena dei codici di tracciamento

Gli stati sono codificati come interi:

```text
CAST = 1
SPOILED = 2
```

e i codici sono:

```text
code_0 = H(Q_bar)

code_i = H(code_(i-1), i, stato_i, h_i)
```

dove `h_i` è l'impronta della scheda `i`. Ogni codice dipende da tutti i precedenti: togliere, aggiungere, riordinare o modificare una riga rompe la catena.

L'elettore riceve il codice della propria scheda e controlla che compaia sulla bacheca con stato CAST.

## Regole di accettazione

Una scheda viene pubblicata solo se:

1. le prove R1-R5 sono valide per il layout della sua circoscrizione, con contesto `Q_bar`;
2. la tupla completa dei suoi cifrati non coincide con quella di una scheda già presente, depositata o sprecata;
3. se è SPOILED, il witness rivelato ricifra esattamente i suoi cifrati;
4. se è CAST, non rivela nessun witness.

La regola 2 blocca la copia di una scheda altrui (Cortier e Smyth, 2011): chi ricopia la scheda di un elettore vota come lui e, in una circoscrizione piccola, può scoprirne il voto. Basta confrontare la scheda intera: ogni cifrato compare in una prova R2 o R3 insieme ad altri cifrati, e costruire quella prova richiede la randomness di tutti i cifrati coinvolti. Copiare solo una parte della scheda è quindi impossibile senza conoscerne i nonce.

## Aventi diritto

La lista degli aventi diritto (`VoterRoll`) è tenuta dal seggio e non viene pubblicata: associa ogni elettore alla sua circoscrizione e registra chi ha votato. Ogni elettore deposita una sola scheda CAST; le schede sprecate non consumano il diritto di voto. La bacheca non contiene identificativi degli elettori.

## Controllo V4

Il verificatore ricalcola `code_0`, ogni impronta `h_i` e ogni codice `code_i`, e controlla che le posizioni siano `1, 2, ..., N`.

---

# 45. Conteggio e decifratura per circoscrizione

Modulo: `evoto/urna.py` (Persona B).

## Totali cifrati

Per la circoscrizione `d`, ogni casella (in ordine canonico) viene aggregata sulle schede CAST della circoscrizione:

```text
(A, B) = (∏ alpha_j, ∏ beta_j)
```

Le schede SPOILED non vengono contate. Una circoscrizione senza schede ha tutti i totali pari a `(1, 1)`.

```python
@dataclass(frozen=True)
class DistrictTally:
    district_index: int
    ballot_count: int                    # schede CAST aggregate
    list_tallies: tuple[Ciphertext, ...]
    blank_tally: Ciphertext
    preference_tallies: tuple[Ciphertext, ...]
```

## Decifratura

Ogni totale viene decifrato con il protocollo della sezione 23, con `max_total = ballot_count` per il logaritmo discreto. Prima di combinarle, ogni share viene verificata con la chiave di verifica ricavata dagli impegni.

```python
@dataclass(frozen=True)
class DistrictResult:
    district_index: int
    ballot_count: int
    list_votes: tuple[int, ...]
    blank_votes: int
    preference_votes: tuple[int, ...]
    decryption_shares: tuple[tuple[DecryptionShare, ...], ...]
```

`decryption_shares[k]` contiene le share dei garanti presenti per il k-esimo totale in ordine canonico.

## Controlli V5, V6 e V7

- V5: il verificatore ricalcola i totali cifrati di ogni circoscrizione dalle schede CAST della bacheca e li confronta con quelli pubblicati.
- V6: verifica ogni share come nella sezione 23.
- V7: controlla che per ogni totale valga `B / M = g^t`, con `t` il totale pubblicato.

---

# 46. Scrutinio

Modulo: `evoto/scrutinio.py` (Persona B).

Versione semplificata e dichiarata della legge: tutti i numeri vengono dalla configurazione, tutti i confronti con le soglie sono esatti (frazioni), il calcolo è deterministico e il verificatore può rifarlo identico (V8).

## Metodo dei quozienti interi e dei più alti resti

Per ripartire `S` seggi tra voti `v_1, ..., v_n` con totale `T > 0`:

```text
seggi_i = floor(v_i · S / T)
resto_i = (v_i · S) mod T
```

I seggi rimasti vanno ai resti più alti. A parità di resto vince chi ha più voti; a parità di voti chi viene prima nell'ordine.

## Passaggi

1. **Voti nazionali.** Per ogni lista si sommano i voti delle circoscrizioni. I voti validi `V` sono la somma dei voti di lista; le schede bianche sono contate a parte.
2. **Voti delle coalizioni.** Somma dei voti di tutte le liste della coalizione.
3. **Soglie.** Una lista supera la soglia di lista se ha voti `> 0` e almeno `list_threshold · V`. Una coalizione è ammessa se ha almeno `coalition_threshold · V` voti e almeno una lista sopra la soglia di lista; i voti di tutte le sue liste contano per la coalizione, ma solo le liste sopra soglia ricevono seggi. Una lista non coalizzata, o di una coalizione non ammessa, corre da sola se supera la soglia di lista.
4. **Competitori.** Prima le coalizioni ammesse, poi le liste singole ammesse, ciascuna nell'ordine della configurazione. Se non ce n'è nessuno lo scrutinio si ferma.
5. **Premio.** Il competitore più votato riceve il premio se è l'unico primo e ha almeno `bonus_threshold · V` voti. Il premio vale `ceil(bonus_seat_share · S)` seggi. Se il riparto proporzionale gli dà già almeno quei seggi, il premio non si applica. Altrimenti il vincitore riceve i seggi del premio e gli altri competitori si ripartiscono i seggi rimanenti con i più alti resti.
6. **Senza premio.** I seggi si ripartiscono tra tutti i competitori con i più alti resti.
7. **Liste delle coalizioni.** I seggi di una coalizione si ripartiscono tra le sue liste sopra soglia, con i più alti resti sui voti di lista.
8. **Circoscrizioni.** I seggi di ogni lista si ripartiscono tra le circoscrizioni con i più alti resti sui suoi voti in ciascuna, senza superare il numero di candidati della lista in quella circoscrizione. I seggi in eccesso passano alle circoscrizioni con posto, nell'ordine dei resti più alti (a parità, più voti e poi indice minore), un seggio per circoscrizione a ogni giro. Se i candidati non bastano lo scrutinio si ferma.
9. **Eletti.** In ogni circoscrizione il primo seggio di una lista va al capolista; gli altri ai candidati con più preferenze, a parità di preferenze a chi è più in alto nella lista.

Semplificazione dichiarata: il numero di seggi di ogni circoscrizione non è fissato in anticipo, ma risulta dalla distribuzione dei seggi delle liste.

## Risultato

```python
@dataclass(frozen=True)
class ScrutinyResult:
    valid_votes: int
    blank_votes: int
    list_votes: tuple[int, ...]
    coalition_votes: tuple[int, ...]
    competitors: tuple[Competitor, ...]
    competitor_seats: tuple[int, ...]
    bonus_competitor: int | None
    list_seats: tuple[int, ...]
    district_list_seats: tuple[tuple[int, ...], ...]
    elected: tuple[ElectedCandidate, ...]
```

---

# 47. Dati pubblici per il registro

Il formato JSON del registro e il suo parser nel verificatore sono di Persona A (`registro.py`). Questa sezione elenca cosa il registro deve contenere.

| Dato | Da dove viene | Controllo |
|---|---|---|
| configurazione dell'elezione (sezione 42) | `config/*.json` | base di tutto |
| `p`, `q`, `g` | `GroupParameters` | V1 |
| `n`, `quorum`, `e`, `Q`, `Q_bar` | cerimonia | V1, V2 |
| `GuardianRecord` di ogni garante: indice, impegni, prove di Schnorr `(h, c, z)` | `KeyCeremony.records` | V2 |
| chiave pubblica `K` | `KeyCeremony.joint_public_key` | V1, V2 |
| bacheca: `extended_base_hash`, `genesis_code`, righe complete (sezione 44) | `BulletinBoard` | V3, V4 |
| totali cifrati di ogni circoscrizione | `DistrictTally` | V5 |
| totali in chiaro e share di decifratura con prove `(a, b, c, z)` | `DistrictResult` | V6, V7 |
| risultato dello scrutinio | `ScrutinyResult` | V8 |

Non vanno mai nel registro:

```text
coefficienti dei polinomi dei garanti (Guardian)
share P_i(l) e share aggregate s_l (KeyCeremony.secret_shares)
witness delle schede CAST
lista degli aventi diritto (VoterRoll)
```

---

# 48. Stato del progetto (v0.6)

```text
F0 ambiente e repository                          completata
F1 specifica condivisa                            completata
F2 gruppo, ElGamal, prove, T1-T4                  completata (A)
F3 garanti e decifratura a soglia                 completata (B)
F4 scheda politica e prove R1-R5                  completata (A)
F5 configurazione, voto, bacheca, scrutinio, E1   completata (B)
F6 verificatore indipendente, E3, E4              completata (A)
F7 cabina web, notebook, misure                   in corso (B, con A): E2, E5 e notebook completati
```

Esperimento E1: `demo.py` esegue un'elezione simulata sulla configurazione di esempio e confronta il risultato cifrato con un conteggio in chiaro; `test/test_elezione.py` esegue lo stesso controllo in forma automatizzata.

La simulazione conserva inoltre i `DistrictTally` cifrati in `SimulationReport.tallies`, così da poterli pubblicare nel registro e confrontare in V5 con i tally ricalcolati dalle sole schede `CAST`.

T4 è completato: sugli stessi plaintext e nonce, i ciphertext aggregati prodotti da `evoto` coincidono con quelli di ElectionGuard e il totale decifrato coincide con il conteggio in chiaro.

F6 è completata.

Il registro pubblico JSON contiene esclusivamente i dati necessari alla verifica universale e non pubblica coefficienti segreti dei polinomi dei garanti, share aggregate segrete, `VoterRoll` o witness delle schede `CAST`.

Il verificatore indipendente:

- usa soltanto la libreria standard Python e `gmpy2`;
- non importa alcun modulo `evoto`;
- legge il registro pubblico JSON;
- esegue autonomamente i controlli V1-V8;
- ricostruisce `Q`, `Q_bar`, la chiave pubblica congiunta `K` e le verification key dei garanti;
- verifica le prove di Schnorr dei garanti;
- verifica le prove R1-R5 di ogni scheda;
- verifica la catena della bacheca, le sequenze e i tracking code;
- verifica il cast-or-spoil ricifrando i witness delle schede `SPOILED`;
- rifiuta la pubblicazione di witness per le schede `CAST`;
- rileva schede cifrate duplicate;
- ricalcola i tally usando esclusivamente le schede `CAST`;
- verifica le prove di Chaum-Pedersen delle share di decifratura;
- ricombina le share tramite i coefficienti di Lagrange;
- verifica i totali in chiaro;
- riesegue deterministicamente lo scrutinio;
- confronta voti, seggi ed eletti con il risultato pubblicato;
- restituisce gli esiti separati `V1`-`V8` e l'esito complessivo `overall`.

L'esperimento E3 è coperto da test di manomissione mirati su prove dei garanti, prove delle schede, tracking code, tally cifrati, prove di decifratura, totali in chiaro, witness delle schede `SPOILED` e risultato dello scrutinio.

L'esperimento E4 è coperto dai test della scheda e del verificatore: configurazioni che violano i vincoli R3-R5 non possono produrre una scheda valida e prove manomesse vengono rifiutate dal verificatore indipendente.

In `gruppo.py` è inoltre disponibile `DEMO_PARAMS`, un gruppo MODP con `p` da 2048 bit e `q` da 256 bit. L'intero protocollo, dalla simulazione alla verifica indipendente V1-V8 del registro pubblico, è testato end-to-end anche con questi parametri.

Gli esperimenti E2 (garanti assenti) ed E5 (costi di una scheda) sono in `esperimenti/` e sono descritti nella sezione 50. Il notebook didattico è descritto nella sezione 51.

## Prossimi passi

Persona A:

- supporto a F7 per l'integrazione del verificatore nella demo: comando `python -m verifica <registro.json>` che stampi l'esito di V1-V8;
- collaborazione alle misure dell'esperimento E5: tempi del verificatore indipendente e osservazione sui controlli di appartenenza (sezione 50);
- preparazione del materiale relativo alla verifica indipendente per tesina e presentazione.

Persona B:

- cabina elettorale e bacheca web (`cabina/`).

Gli esperimenti E2 ed E5 (sezione 50) e il notebook didattico (sezione 51) di Persona B sono completati.

---

# 49. Storico delle versioni

| Versione | Contenuto |
|---|---|
| 0.1 | Specifica condivisa di F1 |
| 0.2 | Decisioni per F3: modello a share aggregate (sezione 23), contesti e input di Fiat-Shamir (sezioni 35 e 36), tipi condivisi e chiave pubblica come `int` (sezioni 20 e 27), convenzioni su garanti e controlli (sezioni 18, 19 e 37), nota su T2 (sezione 26), esempio numerico (sezione 38) |
| 0.3 | Scheda politica F4 (sezione 40), nucleo del verificatore (sezione 41), F5: configurazione (42), voto e sfida di Benaloh (43), bacheca (44), spoglio per circoscrizione (45), scrutinio (46), dati del registro (47), stato del progetto (48); nonce 0 nei cifrati derivati (sezione 16) |
| 0.4 | Riallineamento pre-F6: `e = election_id`; limiti R4/R5 parametrizzati tramite `BallotLayout` e configurazione; verificatore indipendente allineato ai limiti dinamici e irrobustito sugli input; prodotto vuoto dei ciphertext pari a `(1, 1)`; `SimulationReport` conserva i `DistrictTally`; workflow Git aggiornato con merge autonomo consentito dopo test e rispetto della specifica |
| 0.5 | Chiusura F6: registro pubblico JSON completo; parser e verificatore indipendente V1-V8; verifica cast-or-spoil e rilevamento duplicati; test E3 di manomissione ed E4 sui client non validi; T4 completato contro ElectionGuard; parametri demo MODP 2048/256 bit; test end-to-end del registro con `DEMO_PARAMS`; ottimizzazione delle esponenziazioni modulari del verificatore tramite `gmpy2.powmod` |
| 0.6 | F7 in corso: esperimenti E2 (garanti assenti) ed E5 (costi di una scheda), sezione 50; notebook didattico, sezione 51 |

---

# 50. Esperimenti E2 ed E5 (F7)

Moduli: `esperimenti/e2_garanti_assenti.py` ed `esperimenti/e5_costi.py` (Persona B).

Si eseguono dalla radice del repository:

```text
uv run python -m esperimenti.e2_garanti_assenti
uv run python -m esperimenti.e5_costi
```

Gli esperimenti non modificano la libreria e ne usano solo le interfacce pubbliche. Test: `test/test_esperimento_e2.py` e `test/test_esperimento_e5.py`.

## E2 — Garanti assenti

Prima parte: lo stesso risultato con qualunque gruppo di garanti che raggiunga il quorum.

```text
1. simulate_election con n = 5, k = 3 e garanti presenti {1, 2, 3}
2. per ogni S ⊆ {1, ..., 5} con |S| >= 3 (16 gruppi):
     risultati_S = decrypt_district_tally(tally_d, ..., S)   per ogni circoscrizione d
     scrutinio_S = run_scrutiny(config, risultati_S)
     confronto con il conteggio in chiaro: totali, seggi ed eletti
     verify_public_registry sul registro con risultati_S e scrutinio_S
3. per ogni S con |S| = 2 (10 gruppi): la decifratura deve essere rifiutata
```

I totali cifrati sono sempre gli stessi: cambiano soltanto le share `M_l` e i coefficienti `λ_l`.

Seconda parte: meno di `k` share non rivelano nulla sul segreto. Nel gruppo didattico si considera il polinomio della cerimonia

```text
S(x) = a_0 + a_1 x + ... + a_(k-1) x^(k-1) mod q        s = S(0) = a_0
```

e, date le share aggregate di alcuni garanti, si enumerano tutti i `(a_1, ..., a_(k-1))` in `Z_q^(k-1)`: la prima share fissa `a_0`, e il polinomio è compatibile se passa anche per le altre share note. Con `m < k` share note ogni segreto ha esattamente `q^(k-1-m)` polinomi compatibili; con `m = k` ne resta uno solo.

Con `k = 3` e `q = 1289`:

| Share note | Segreti compatibili | Polinomi per segreto |
|---|---|---|
| {1} | 1289 | 1289 |
| {1, 2} | 1289 | 1 |
| {1, 2, 3} | 1 | 1 |

Il segreto ottenuto con Lagrange da `k` share soddisfa `g^s = K`; forzando Lagrange con `k - 1` share si ottiene un valore `s'` con `g^(s') ≠ K`.

La proprietà è informativa per Shamir. Con gli impegni di Feldman la chiave `K = g^s` è pubblica, quindi nel sistema completo la segretezza del segreto è computazionale: ricavarlo richiede un logaritmo discreto. L'enumerazione costa `q^(k-1)` passi ed è possibile solo nel gruppo didattico.

## E5 — Costi di una scheda

Scheda con `L` liste, `c` candidati per lista oltre al capolista, `G` generi, al massimo `P` preferenze e `P_g` per genere:

```text
cifrati   m     = L + 1 + L·c
prove           = m (R1) + 1 (R2) + L·c (R3) + 1 (R4) + G (R5)
rami            = 2m + 1 + 2·L·c + (P + 1) + G·(P_g + 1)
```

Scheda di riferimento della proposta di progetto (`L = 10`, `c = 8`, `G = 2`, `P = 3`, `P_g = 2`): 91 cifrati, 175 prove, `182 + 1 + 160 + 4 + 6 = 353` rami. Le misure contano cifrati, prove e rami sulla scheda vera prodotta da `prepare_ballot`.

Dimensione in byte, con `e` byte per un elemento del gruppo (quelli di `p`) e `s` byte per una sfida o una risposta (quelli di `q`):

```text
con impegni      = (2m + 2·rami)·e + 2·rami·s
forma compatta   = 2m·e + 2·rami·s
```

Il registro pubblica le prove con gli impegni, come ElectionGuard. Nella forma compatta gli impegni non vengono trasmessi, perché si ricalcolano dalle equazioni di verifica a partire da sfida e risposta: è una stima della dimensione, il formato non è implementato.

Tempi: mediana di più esecuzioni di `prepare_ballot` (cifratura e prove) e `verify_ballot` (controllo R1-R5). Le esponenziazioni modulari si contano sostituendo temporaneamente `mod_pow` nei moduli `gruppo`, `elgamal`, `prove`, `garanti` e `decifratura` (`unittest.mock.patch`); quelle con esponente `q` sono controlli di appartenenza al sottogruppo. Il conteggio comprende anche le `g^v` con `v` piccolo (al massimo `P`), di costo trascurabile. Per il confronto con Python puro la stessa sostituzione usa `pow()` al posto di `gmpy2.powmod`.

Il gruppo da 4096 bit è quello standard di ElectionGuard (`q = 2^256 - 189`), definito in `esperimenti/e5_costi.py` solo per le misure.

Proiezione su una circoscrizione di `N` elettori:

```text
bacheca       = N · dimensione di una scheda
verifica      = N · tempo di verifica di una scheda          (un core)
conteggio     = N · m · tempo di una moltiplicazione di cifrati
decifratura   = m · tempo di decifratura di un totale
                (k share con prove, loro verifica, Lagrange, BSGS fino a N)
```

Risultati indicativi sulla scheda di riferimento, misurati su un portatile (su un'altra macchina cambiano i tempi, non le dimensioni né il numero di esponenziazioni):

| Configurazione | Dimensione | Cifratura | Verifica |
|---|---|---|---|
| 4096 bit, con impegni, Python puro | 477 KB | 27 s | 39 s |
| 4096 bit, forma compatta, `gmpy2` | 116 KB | 1,5 s | 2,0 s |
| 2048/256 bit, forma compatta, `gmpy2` | 69 KB | 0,4 s | 0,6 s |
| 2048/256 bit, con impegni, `gmpy2` | 250 KB | 0,4 s | 0,6 s |

Cifrare la scheda richiede 2129 esponenziazioni, verificarla 2996. Con `N = 1.000.000` e il gruppo da 2048 bit: bacheca di circa 70 GB in forma compatta, circa 165 ore di verifica su un core, circa 45 minuti di conteggio omomorfico, pochi secondi di decifratura. `gmpy2` è da 8 a 20 volte più veloce di `pow()`, a seconda della macchina.

Osservazione sui controlli di appartenenza. Dei 2996 controlli della verifica, 1231 sono `x^q = 1`: 706 sugli impegni dei rami, 350 sulle componenti dei cifrati (182 originali e 168 derivati per R2-R5) e 175 sulla chiave `K`, una volta per prova. Il controllo degli impegni è implicato dalle equazioni di verifica: se `g^z = a · alpha^c` vale e `g`, `alpha` stanno nel sottogruppo, anche `a` vi appartiene. Anche i cifrati derivati, prodotti di elementi già controllati, e i controlli ripetuti su `K` sono ridondanti. Basterebbe controllare una volta `K` e le 182 componenti dei cifrati originali, con un risparmio di circa un terzo delle esponenziazioni della verifica. È una possibile ottimizzazione di `prove.py` e del verificatore (Persona A), non implementata.

---

# 51. Notebook didattico (F7)

File: `notebook/demo_didattica.ipynb` (Persona B). Test: `test/test_notebook.py`.

Il notebook ripercorre il protocollo con il gruppo didattico e i valori della sezione 38. Ogni cella di codice usa la libreria `evoto` e controlla con `assert` i valori della specifica:

| Sezione | Contenuto | Valori controllati |
|---|---|---|
| 1 | Gruppo di ordine primo, controllo di appartenenza | `p = 2q + 1`, `g^q = 1` |
| 2 | Con `g = 2` (ordine pari) il simbolo di Legendre rivela la parità del voto (Mosca 2019); con `g = 4` vale sempre 1 | voti ricostruiti, simboli `{1}` |
| 3-4 | ElGamal esponenziale con `s = 765` e conteggio omomorfico | `K = 530`, cifrati della sezione 38, `(A, B) = (1196, 154)`, `t = 2` |
| 5 | Shamir con dealer, `P(x) = 765 + 100x` | share 865, 965, 1065; `λ_1 = 646`, `λ_3 = 644`; `M = 332` per ogni gruppo di garanti |
| 6 | Cerimonia senza dealer con i polinomi della sezione 38 | impegni, `Q = 889`, Schnorr `(910, 957, 949)`, share `P_i(l)`, `s_l`, `V_l`, `K = 530`, `Q_bar = 744` |
| 7 | Share di decifratura con Chaum-Pedersen, garante assente, share alterata, una sola share | `M_1 = 60`, prova `(910, 1033, 524, 828)`, `t = 2` |
| 8 | Prova OR per `Enc(1)` costruita a mano (`u = 7`, ramo simulato con sfida 100 e risposta 200) e accettata da `verify_value_in_set` | sfida `c = c_0 + c_1`; nessuna prova per `Enc(2)` |
| 9 | Scheda con due liste di due candidati: 7 cifrati, 15 prove; preferenza fuori lista rifiutata da R3; *Italian attack* | `(7, 1, 4, 1, 2)` prove, 93 combinazioni |
| 10 | Bacheca: scheda sprecata e ricifrata, due schede depositate, catena dei codici, riga alterata, scheda ricopiata | catena valida e poi non valida |
| 11 | Elezione simulata sulla configurazione di esempio, registro pubblico, verificatore indipendente, manomissione | `overall` vero; V7 e V8 falsi dopo la manomissione |

Le uscite pubblicate vengono da un'esecuzione completa e in ordine. I nonce delle cifrature sono fissati, quindi rieseguendo il notebook le uscite non cambiano; restano casuali solo le parti delle prove che non vengono stampate.

Jupyter non è una dipendenza del progetto. Il notebook si apre con:

```text
uv run --with jupyter jupyter lab notebook/demo_didattica.ipynb
```

La prima cella aggiunge agli import la radice del repository, perché il progetto non è installato come pacchetto. Il test esegue tutte le celle con il solo interprete Python, partendo dalla cartella del notebook come Jupyter, e controlla che le uscite salvate vengano da un'esecuzione completa senza errori.
