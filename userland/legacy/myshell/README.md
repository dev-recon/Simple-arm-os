# MyShell

Un shell Unix simple et fonctionnel ecrit en C, compatible avec le standard GNU89.

## Fonctionnalites

### Fonctionnalites de base
- OK Execution de commandes externes
- OK Commandes integrees (builtins)
- OK Redirections (`<`, `>`, `>>`)
- OK Pipes (`|`)
- OK Execution en arriere-plan (`&`)
- OK Operateurs logiques (`&&`, `||`)
- OK Separateur de commandes (`;`)

### Variables et expansion
- OK Variables d'environnement (`$VAR`, `${VAR}`)
- OK Variables speciales (`$?`, `$`, `$#`, `$0-$9`)
- OK Expansion du tilde (`~`, `~user`)
- OK Protection par guillemets (`"`, `'`)

### Controle des jobs
- OK Jobs en arriere-plan
- OK Commande `jobs` pour lister les jobs
- OK Commandes `fg` et `bg`
- OK Gestion des signaux (Ctrl+C, Ctrl+Z)

### Historique
- OK Historique des commandes
- OK Commande `history`
- OK Sauvegarde/chargement automatique

### Personnalisation
- OK Prompt personnalisable (PS1)
- OK Fichiers de configuration (~/.myshellrc)
- OK Variables locales du shell

## Compilation

```bash
# Compilation simple
make

# Compilation avec debug
make CFLAGS="-Wall -Wextra -std=gnu89 -g"

# Installation
sudo make install
```

## Utilisation

### Lancement
```bash
# Lancement interactif
./bin/myshell

# Execution d'un script
./bin/myshell script.sh

# Execution d'une commande
echo "ls -la" | ./bin/myshell
```

### Commandes integrees

| Commande | Description | Exemple |
|----------|-------------|---------|
| `cd [dir]` | Changer de repertoire | `cd /tmp`, `cd ~`, `cd -` |
| `pwd` | Afficher le repertoire courant | `pwd` |
| `echo [-n] [args...]` | Afficher du texte | `echo "Hello World"` |
| `export VAR[=value]` | Exporter une variable | `export PATH=/usr/bin` |
| `unset VAR` | Supprimer une variable | `unset PATH` |
| `env` | Afficher les variables d'environnement | `env` |
| `history [-c]` | Afficher/effacer l'historique | `history`, `history -c` |
| `jobs` | Afficher les jobs | `jobs` |
| `fg [%job]` | Mettre un job au premier plan | `fg %1` |
| `bg [%job]` | Continuer un job en arriere-plan | `bg %1` |
| `test expr` | evaluer une expression | `test -f file.txt` |
| `true` | Retourner vrai | `true` |
| `false` | Retourner faux | `false` |
| `source file` | Executer un fichier | `source ~/.myshellrc` |
| `help [cmd]` | Afficher l'aide | `help`, `help cd` |
| `exit [code]` | Quitter le shell | `exit 0` |

### Exemples d'utilisation

```bash
# Commandes de base
myshell$ ls -la
myshell$ cd /tmp && pwd
myshell$ echo "Hello" > file.txt
myshell$ cat file.txt

# Pipes et redirections
myshell$ ls -la | grep myshell
myshell$ ls > files.txt 2>&1
myshell$ sort < files.txt

# Variables
myshell$ export NAME="World"
myshell$ echo "Hello $NAME"
myshell$ echo "PID: $, Last exit: $?"

# Jobs
myshell$ sleep 100 &
[1] 12345
myshell$ jobs
[1]+  Running    sleep 100 &
myshell$ fg %1

# Operateurs logiques
myshell$ test -f file.txt && echo "File exists"
myshell$ false || echo "This will run"
myshell$ ls /nonexistent; echo "Status: $?"
```

## Prompt personnalise

Le prompt peut etre personnalise avec la variable `PS1`. Sequences d'echappement supportees :

| Sequence | Description |
|----------|-------------|
| `\u` | Nom d'utilisateur |
| `\h` | Nom d'hote (court) |
| `\H` | Nom d'hote (complet) |
| `\w` | Repertoire de travail complet |
| `\W` | Nom du repertoire de travail |
| `\ | ` si utilisateur normal, `#` si root |
| `\t` | Heure (HH:MM:SS) |
| `\d` | Date (Jeu 23 Mai) |
| `\n` | Nouvelle ligne |
| `\!` | Numero de commande dans l'historique |
| `\?` | Code de sortie de la derniere commande |

Exemple :
```bash
export PS1="[\u@\h \W]\$ "
export PS1="\t \w > "
```

## Configuration

### Fichier ~/.myshellrc

Creer un fichier `~/.myshellrc` pour personnaliser MyShell :

```bash
# Prompt personnalise
export PS1="[\u@\h \W]\$ "

# Variables d'environnement
export EDITOR=nano
export PAGER=less

# Message de bienvenue
echo "Bienvenue dans MyShell!"

# Variables personnalisees
export MYVAR="valeur"
```

### Variables d'environnement importantes

- `PS1` : Prompt principal
- `PS2` : Prompt de continuation
- `PATH` : Chemin de recherche des commandes
- `HOME` : Repertoire utilisateur
- `USER` : Nom d'utilisateur

## Tests

```bash
# Tests automatiques
make test

# Tests manuels
echo 'echo "Test 1: Echo"' | ./bin/myshell
echo 'export VAR=test && echo $VAR' | ./bin/myshell
echo 'ls | head -3' | ./bin/myshell
```

## Debug

```bash
# Compilation debug
make CFLAGS="-Wall -Wextra -std=gnu89 -g -DDEBUG"

# Utilisation avec gdb
make debug

# Verification memoire
make valgrind
```

## Limitations

- Pas de support des alias
- Pas d'auto-completion
- Pas de navigation dans l'historique avec les fleches
- Pas de support des expressions arithmetiques
- Pas de globbing avance (*, ?, [])
- Pas de substitution de commandes ($(cmd))

## Architecture

```
myshell/
├── include/
│   └── shell.h          # Definitions et prototypes
├── src/
│   ├── main.c           # Point d'entree principal
│   ├── parser.c         # Analyse lexicale et syntaxique
│   ├── executor.c       # Execution des commandes
│   ├── builtins.c       # Commandes integrees
│   ├── variables.c      # Gestion des variables
│   ├── history.c        # Historique des commandes
│   ├── jobs.c           # Controle des jobs
│   ├── signals.c        # Gestion des signaux
│   ├── rcfiles.c        # Fichiers de configuration
│   └── prompt.c         # Gestion du prompt
├── Makefile            # Script de compilation
└── README.md           # Cette documentation
```

## Compatibilite

- **Standards** : C89/C90, POSIX.1
- **Compilateurs** : GCC, Clang
- **Systemes** : Linux, macOS, *BSD
- **Architectures** : x86, x86_64, ARM

## Auteur

MyShell - Un shell educatif implementant les fonctionnalites essentielles d'un shell Unix.

## Licence

Ce projet est sous licence libre. Voir le fichier LICENSE pour plus de details.

## Contribution

Les contributions sont les bienvenues ! Pour contribuer :

1. Fork le projet
2. Creer une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit les changements (`git commit -m 'Add AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## Roadmap

### Version future
- [ ] Auto-completion
- [ ] Navigation dans l'historique
- [ ] Support des alias
- [ ] Globbing (*, ?, [])
- [ ] Substitution de commandes
- [ ] Expressions arithmetiques
- [ ] Configuration avancee
- [ ] Mode vi/emacs pour l'edition de ligne