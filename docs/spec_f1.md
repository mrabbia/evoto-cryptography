# eVoto — Specifica tecnica condivisa F1

**Versione:** 0.1  
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

Se un garante possiede il contributo segreto `s_i`:

```text
K_i = g^(s_i)

M_i = A^(s_i)
```

deve poter dimostrare:

```text
log_g(K_i) = log_A(M_i)
```

senza rivelare `s_i`.

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

Dato:

```text
(A, B)
```

ogni garante produce il proprio contributo di decifratura.

Concettualmente:

```text
M_i = A^(s_i)
```

accompagnato da una prova Chaum-Pedersen.

Le share valide vengono combinate secondo il protocollo a soglia.

Alla fine si ottiene:

```text
B / M = g^t
```

dove:

```text
t = totale dei voti
```

Il valore ottenuto non è direttamente `t`, ma `g^t`.

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

Tipi previsti, i cui campi verranno fissati durante l'implementazione:

```text
PublicKey
SchnorrProof
ChaumPedersenProof
ValueSetProof
Guardian
DecryptionShare
```

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

inizia F2 con:

```text
feature/group-parameters
```

e successivamente:

```text
evoto/gruppo.py
evoto/elgamal.py
evoto/prove.py
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

Obiettivo congiunto di F2 + F3:

```text
referendum sì/no end-to-end
```

realizzato interamente con la nostra libreria e verificato tramite test.