# Plan étape (a) — Faute anonyme paresseuse pour sys_mmap

Objectif : `mmap(MAP_ANON)` ne mappe plus aucune page à l'appel. Les pages sont
allouées (zéroïsées) et mappées à la première faute d'accès. Périmètre
volontairement réduit : anonyme + privé uniquement, `PROT_EXEC` exclu,
fichiers exclus (étape c), brk exclu (suivi ultérieur).

## 0. État des lieux vérifié (rien à construire ici)

| Prérequis | État | Où |
|---|---|---|
| Prototype de fault-in | ✅ existe | `handle_user_stack_fault`, virtual.c:654 |
| Zero-fill des pages | ✅ gratuit | `allocate_page` memset dans physical.c:160 |
| munmap tolère pages absentes | ✅ | `vm_unmap_range` `if (phys && ...)`, virtual.c:443/456 |
| fork tolère pages absentes | ✅ | `cow_copy_vma` `if (!phys) continue`, virtual.c:561 |
| VMA flags copiés au fork | ✅ | `fork_vm_space` → `create_vma(parent flags)` |
| Usercopy sans faute SVC | ✅ par design | walk de tables dans user/userspace.c |
| Rejeu instruction fautive | ✅ | vecteur data abort, boot.S (retour 0 → subs pc, lr, #8) |

## 1. Nouveau flag VMA (include/kernel/memory.h)

```c
#define VMA_LAZY    (1 << 5)   /* pages allouées à la faute, pas au mmap */
```

Explicite plutôt qu'inféré : une VMA sans le flag garde la sémantique eager.
`vm_unmap_range` (split : `*right = *vma`) et `fork_vm_space` propagent déjà
les flags — aucun changement nécessaire pour la cohérence du flag.

## 2. Le handler de faute (kernel/memory/virtual.c)

Nouvelle fonction, généralisation directe de `handle_user_stack_fault` :

```c
int handle_lazy_anon_fault(uint32_t fault_addr, bool is_write)
```

Logique :
1. task/process/vm valides sinon -EINVAL (même préambule que stack fault).
2. `find_vma(vm, fault_addr)` ; exiger `VMA_LAZY`, sinon -EINVAL.
3. Permissions : `is_write` → exiger `VMA_WRITE` ; lecture → exiger `VMA_READ`.
   Sinon -EACCES (le SIGSEGV existant prend le relais).
4. PTE déjà présent → -EEXIST (faute concurrente déjà résolue ou vraie
   permission fault mal routée : ne jamais écraser).
5. `allocate_page()` (zéroïsée) ; NULL → -ENOMEM → SIGSEGV du processus
   fauteur (politique assumée, pas d'OOM-killer ; documenter dans STABILITY.md).
6. `map_user_page(vm->pgdir, vaddr, phys, vma->flags, vm->asid)`.

Note TLB : transition invalide→présent = aucun shootdown nécessaire (ARMv7 ne
cache pas les entrées invalides). Vérifier que `map_user_page` n'en émet pas ;
si si, utiliser/créer la variante sans flush pour ce chemin chaud.

## 3. Dispatch dans data_abort_handler (kernel/interrupt/exception.c:965)

Après la tentative stack fault, même garde (translation fault + mode user) :

```c
if ((status == 0x05 || status == 0x07) && mode == 0x10) {
    if (handle_user_stack_fault(dfar) == 0) { ... return 0; }
    if (handle_lazy_anon_fault(dfar, is_write) == 0) {
        if (task) { task->page_faults++; task->lazy_faults++; }
        return 0;
    }
}
```

`is_write` (DFSR bit 11) est déjà extrait ligne 960. Ajouter le compteur
`lazy_faults` dans task_t à côté de `stack_faults`/`cow_faults`.

## 4. sys_mmap (kernel/syscalls/process_syscalls.c:2613)

Pour `ARMOS_MAP_ANON` :
- `vma_flags |= VMA_LAZY;` **sauf si `prot & ARMOS_PROT_EXEC`** (voir §7 —
  le prefetch abort handler ne sait pas récupérer ; PROT_EXEC reste eager).
- supprimer la boucle d'allocation eager (`allocate_page`/`map_user_page`)
  pour le cas lazy ; `create_vma` suffit.
- chemin fichier (fd ≥ 0) : inchangé (eager + read), étape (c) plus tard.

L'échec partiel de la boucle eager (rollback `vm_unmap_range`) disparaît du
chemin anonyme : plus de risque d'ENOMEM à moitié mappé, l'ENOMEM se paie à
la faute, page par page.

## 5. Usercopy — le point le plus délicat (kernel/user/userspace.c)

Le kernel ne prend JAMAIS de faute sur la mémoire user depuis SVC : il marche
les tables et copie via le direct mapping. Toute vérification
`get_physical_address(...) == 0 → échec` devient un faux EFAULT sur une page
lazy jamais touchée. À traiter :

1. `fault_in_user_write_range` (userspace.c:171) : appelle déjà
   `handle_user_stack_fault` pour les trous ; ajouter le fallback
   `handle_lazy_anon_fault(page, true)`. Couvre `read(fd, buf_mmap_intact, n)`.
2. Chemin lecture (`copy_from_user` / `copy_to_user_pages`, userspace.c:202 :
   `!phys → -1`) : ajouter le même fallback en lecture
   (`handle_lazy_anon_fault(page, false)`). Couvre
   `write(fd, buf_mmap_intact, n)` — une page zéro mappée est la sémantique
   correcte. (Optimisation "lire des zéros sans mapper" : hors périmètre.)
3. `is_valid_user_range`-style walks (userspace.c:157) : décider par call-site
   — valider la plage via VMA (couvre lazy) plutôt que via PTE.
4. **Audit exhaustif** : `grep -rn get_physical_address kernel/` — 8 fichiers.
   À examiner un par un : virtual.c, helpers.c, mmu.c, userspace.c, shm.c,
   process_syscalls.c, exec.c, signal.c. Cas notables :
   - signal.c : setup de frame signal sur pile/pages user → doit pré-fauter
     (probablement déjà couvert par le chemin stack, vérifier).
   - coredump (exception.c) : dump d'une région lazy → tolérer les trous
     (skip ou zéros), ne pas échouer le dump.
   - shm.c / exec.c : a priori non concernés (jamais lazy), vérifier que les
     asserts `!phys` ne s'appliquent qu'à leurs propres VMAs.

## 6. Ce qui ne change PAS (à vérifier en revue, pas à coder)

- `destroy_vm_space` (virtual.c:169) : valide chaque page avant free —
  confirmer qu'un trou est ignoré silencieusement (pas de KERROR parasite).
- fork lazy : pages touchées → COW normal ; pages absentes → restent lazy
  chez l'enfant (flags copiés). Rien à faire.
- munmap partiel d'une VMA lazy : split déjà correct.

## 7. Pièges identifiés

1. **PROT_EXEC lazy = crash garanti** : premier fetch → prefetch abort → le
   handler actuel est diagnostic-only (dump + hang). D'où l'exclusion §4.
   Follow-up possible : fault-in dans prefetch_abort_handler (IFAR/IFSR).
2. **SMP aujourd'hui sûr, threads demain** : un processus = une tâche, donc
   un même espace d'adressage ne faute jamais sur deux CPUs en parallèle.
   Le jour où clone() existe, il faudra un verrou de faute par vm_space
   (deux threads fautant la même page → double allocate/map). Poser un
   commentaire dans handle_lazy_anon_fault dès maintenant.
3. **Rejeu d'instruction** : le vecteur data abort rejoue via
   `subs pc, lr, #8` (ARM uniquement). Si du code Thumb user apparaît un
   jour, l'offset diffère — déjà vrai pour stack/COW, pas une régression.
4. **Baselines STABILITY.md** : `phys live` et `+alloc` vont baisser pour les
   mêmes workloads ; `page_faults` par tâche va monter. Mettre à jour la
   baseline après validation, sinon les prochaines chasses aux fuites
   compareront des torchons et des serviettes.

## 8. Ordre des commits (chacun buildable et testable seul)

1. **Infra** : VMA_LAZY + handle_lazy_anon_fault + dispatch abort handler +
   compteur lazy_faults. Aucun setter → zéro changement de comportement.
   Test : boot + matrice habituelle, diff de comportement attendu : néant.
2. **Usercopy** : fallbacks lecture/écriture + audit des call-sites §5.4.
   Toujours aucun setter → toujours aucun changement observable.
3. **Bascule** : sys_mmap pose VMA_LAZY (anonyme, non-EXEC) et perd sa boucle
   eager. C'est LE commit de bascule, petit et révocable (revert = retour
   eager sans toucher à l'infra).
4. **Tests + doc** : mmaptest userland, baselines STABILITY.md, CHANGELOG.

## 9. Plan de test (mmaptest userland + matrice)

Nouveau `userland/coreutils/src/mmaptest.c` (ou tests/) :
1. mmap 16 Mo anonyme → vérifier via `free`/`lps` que phys live ne bouge
   presque pas ; toucher 1 page → +1 ; toucher tout → +4096 pages.
2. Lecture avant écriture : chaque octet doit être 0 (garantie zero-fill).
3. `write(fd, buf, n)` avec buf mmap jamais touché → n octets de zéros
   écrits, pas d'EFAULT (chemin usercopy lecture).
4. `read(fd, buf, n)` dans buf jamais touché → contenu correct
   (chemin fault_in_user_write_range).
5. fork après avoir touché la moitié : parent et enfant écrivent chacun dans
   les deux moitiés → isolation COW + lazy indépendante.
6. munmap partiel (trou au milieu) puis re-touch des bords → OK ;
   accès au trou → SIGSEGV propre.
7. mmap PROT_READ seul, tentative d'écriture → SIGSEGV (pas de fault-in).
8. Boucle mmap/touch/munmap ×10000 → compteurs alloc/free reviennent à
   l'équilibre (pas de fuite : l'invariant `+alloc == -free + live`).
9. Matrice complète : `systest ×5`, `memstress`, `vfstest ×2`, SMP_CPUS=1
   puis 2, quantum 1 ms. `sched-refuse`/`ready-refuse` stables.
10. Ctrl+C pendant une touch-loop mmap (si patch préemption appliqué) :
    le processus meurt proprement, pas de page orpheline (vérifier compteurs).

## 10. Critère de sortie

- Les 10 tests passent en SMP_CPUS=1 et SMP_CPUS=2.
- Aucun nouveau `sched-refuse`, `tty-stale`, ou KERROR au boot et sous stress.
- Baselines STABILITY.md mises à jour et documentées.
- `lazy_faults` visible dans lps/procfs pour l'observabilité future.
