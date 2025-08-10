/* ls_process.c - Processus ls pour votre kernel */
#include <kernel/task.h>
#include <kernel/vfs.h>
#include <kernel/fat32.h>
#include <kernel/kernel.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/kprintf.h>
#include <kernel/task.h>
#include <kernel/process.h>
#include <kernel/syscalls.h>
#include <kernel/ramfs.h>

/* Declarations forward */
void ls_process_main(const char* path);
void test_ramfs_cluster_content(void);
static void setup_ls_process_context(task_t* ls_proc);
int ls_read_directory(const char* path);
//void format_file_entry(dirent_t* entry);
pid_t spawn_ls_process(void);


/**
 * Formate et affiche une entree de fichier
 */
void format_file_entry(dirent_t* entry, file_t *file)
{
    const char* type_str;
    const char* suffix = " ";
    
    switch (entry->d_type) {
        case DT_DIR:
            type_str = "DIR ";
            suffix = "/";
            break;
        case DT_REG:
            type_str = "FILE";
            break;
        case DT_LNK:
            type_str = "LINK";
            suffix = "*";
            break;
        case DT_CHR:
            type_str = "CHAR";
            break;
        case DT_BLK:
            type_str = "BLK ";
            break;
        case DT_FIFO:
            type_str = "FIFO";
            suffix = "|";
            break;
        case DT_SOCK:
            type_str = "SOCK";
            suffix = "=";
            break;
        default:
            type_str = "????";
            break;
    }
   
    
    kprintf("%s  %s %u bytes %s\n", type_str, entry->d_name, file->inode->size, suffix);
}


/**
 * Lit et affiche le contenu d'un repertoire
 */
int ls_read_directory(const char* path)
{
    inode_t* dir_inode;
    file_t dir_file;
    dirent_t dirent;
    int result;
    int entry_count = 0;
    
    kprintf("\n=== Contenu du repertoire %s ===\n", path);
    
    /* Obtenir l'inode du repertoire */
    dir_inode = path_lookup(path);
    if (!dir_inode) {
        kprintf("KO Repertoire '%s' non trouve\n", path);
        return -1;
    }
    
    /* Verifier que c'est bien un repertoire */
    if (!S_ISDIR(dir_inode->mode)) {
        kprintf("KO '%s' n'est pas un repertoire\n", path);
        put_inode(dir_inode);
        return -1;
    }
    
    /* Initialiser la structure file */
    memset(&dir_file, 0, sizeof(file_t));
    dir_file.inode = dir_inode;
    dir_file.flags = O_RDONLY;
    dir_file.offset = 0;
    dir_file.f_op = dir_inode->f_op;
    
    /* Ouvrir le repertoire */
    if (dir_file.f_op && dir_file.f_op->open) {
        result = dir_file.f_op->open(dir_inode, &dir_file);
        if (result < 0) {
            kprintf("KO Impossible d'ouvrir le repertoire\n");
            put_inode(dir_inode);
            return -1;
        }
    }
    
    kprintf("Type  Nom\n");
    kprintf("----- ----------------------\n");
    
    /* Lire les entrees du repertoire */
    while (1) {
        if (!dir_file.f_op || !dir_file.f_op->readdir) {
            kprintf("KO Operation readdir non supportee\n");
            break;
        }
        
        result = dir_file.f_op->readdir(&dir_file, &dirent);
        
        if (result <= 0) {
            if (result < 0) {
                kprintf("KO Erreur lors de la lecture (code: %d)\n", result);
            }
            break;
        }
        
        /* Afficher l'entree */
        format_file_entry(&dirent, &dir_file);
        entry_count++;
        
        /* Limite de securite */
        if (entry_count > 500) {
            kprintf("WARNING  Arret apres 500 entrees (limite de securite)\n");
            break;
        }
    }
    
    kprintf("----- ----------------------\n");
    kprintf("Total: %d entrees\n", entry_count);
    
    /* Fermer le repertoire */
    if (dir_file.f_op && dir_file.f_op->close) {
        dir_file.f_op->close(&dir_file);
    }
    
    put_inode(dir_inode);
    return entry_count;
}



/**
 * Cree et lance le processus ls comme fils du processus init
 */
pid_t spawn_ls_process(void)
{
    task_t* init_proc = current_task;
    task_t* ls_proc;
    pid_t ls_pid;
    
    if (!init_proc) {
        KERROR("[LS] Aucun processus courant pour creer le processus ls\n");
        return -1;
    }
    
    KINFO("[LS] Creation du processus ls depuis le processus %u\n", init_proc->process->pid);
    
    /* Creer le processus fils */
    ls_proc = create_process("ls_proc");
    if (!ls_proc) {
        KERROR("[LS] echec de creation du processus ls\n");
        return -1;
    }
    
    /* Configuration du processus ls */
    ls_proc->process->ppid = init_proc->process->pid;
    ls_proc->state = TASK_READY;
    ls_pid = ls_proc->process->pid;
    
    /* Copier l'espace memoire virtuel (simplifie - pas de COW ici) */
    destroy_vm_space(ls_proc->process->vm);
    ls_proc->process->vm = create_vm_space();
    if (!ls_proc->process->vm) {
        KERROR("[LS] echec de creation de l'espace memoire virtuel\n");
        destroy_process(ls_proc);
        return -1;
    }
    
    /* Copier les descripteurs de fichiers (stdin, stdout, stderr) */
    for (int i = 0; i < 3; i++) {
        if (init_proc->process->files[i]) {
            ls_proc->process->files[i] = init_proc->process->files[i];
            ls_proc->process->files[i]->ref_count++;
        }
    }
    
    /* Configurer le contexte d'execution */
    setup_ls_process_context(ls_proc);
    
    /* Ajouter a la liste des enfants du processus parent */
    ls_proc->process->sibling_next = init_proc->process->children;
    init_proc->process->children = ls_proc;
    ls_proc->process->parent = init_proc;
    
    /* Ajouter a la queue des processus prets */
    add_to_ready_queue(ls_proc);
    
    KINFO("[LS] Processus ls cree avec PID %u\n", ls_pid);
    return ls_pid;
}

/**
 * Configure le contexte d'execution du processus ls
 */
static void setup_ls_process_context(task_t* ls_proc)
{
    /* Initialiser les registres */
    memset(&ls_proc->context, 0, sizeof(ls_proc->context));
    
    /* Point d'entree du processus ls */
    ls_proc->context.pc = (uint32_t)ls_process_main;  /* PC */
    ls_proc->context.sp = USER_STACK_TOP - 16;        /* SP */
    ls_proc->context.lr = 0xDEADBEEF;                          /* LR */
    
    /* CORRECTION: Passer "/" comme premier argument dans r0 */
    /* Allouer une zone memoire pour le path */
    char* root_path = "/";
    //ls_proc->registers[0] = (uint32_t)root_path;         /* r0 = path argument */
    ls_proc->context.r0 = (uint32_t)root_path;         /* r0 = path argument */

    /* Mode utilisateur */
    ls_proc->context.cpsr = 0x13;  /* User mode, ARM state */
    
    KDEBUG("[LS] Contexte configure - PC: 0x%08X, SP: 0x%08X\n", 
           ls_proc->context.pc, ls_proc->context.sp);
}

/**
 * Point d'entree principal du processus ls
 */
void ls_process_main(const char* path)
{
    int result;
    const char* actual_path;
    
    KINFO("[LS] === Demarrage du processus ls (PID %u) ===\n", sys_getpid());
    
    /* CORRECTION: Verifier et corriger le path */
    if (!path || path[0] == '\0' || (unsigned char)path[0] > 127) {
        /* Path corrompu ou invalide - utiliser la racine */
        actual_path = "/";
        KWARN("[LS] Path invalide detecte, utilisation de '/' par defaut\n");
    } else {
        actual_path = path;
    }
    
    //KINFO("[LS] Listing du repertoire: '%s' adresse %p\n", actual_path, &actual_path);
    
    /* Verifier que le systeme de fichiers est monte */
    if (!is_fat32_mounted()) {
        kprintf("[LS] KO Systeme de fichiers non monte\n");
        sys_exit(1);
    }
    
    kprintf("[LS] OK Systeme de fichiers monte (cluster racine: %u)\n", 
            get_fat32_root_cluster());
    
    /* Lister le contenu du repertoire */
    result = ls_read_directory("/");
    
    if (result < 0) {
        kprintf("[LS] KO Erreur lors de la lecture du repertoire '%s'\n", actual_path);
        sys_exit(2);
    }
    
    kprintf("[LS] OK Commande ls terminee avec succes (%d entrees)\n", result);
    sys_exit(0);
}


/**
 * Version synchrone - lance le processus ls et attend sa terminaison
 */
int execute_ls_command_sync(void)
{
    pid_t ls_pid;
    int status;
    pid_t wait_result;
    
    KINFO("[INIT] Lancement synchrone de la commande ls\n");
    
    /* Creer et lancer le processus ls */
    ls_pid = spawn_ls_process();
    if (ls_pid < 0) {
        KERROR("[INIT] echec du lancement du processus ls\n");
        return -1;
    }
    
    KINFO("[INIT] Processus ls lance (PID %u), attente de terminaison...\n", ls_pid);
    
    /* Attendre la terminaison du processus ls */
    wait_result = sys_waitpid(ls_pid, &status, 0);
    
    if (wait_result == ls_pid) {
        KINFO("[INIT] Processus ls termine (PID %u, code: %d)\n", ls_pid, status);
        return status;
    } else {
        KERROR("[INIT] Erreur lors de l'attente du processus ls (code: %d)\n", wait_result);
        return -1;
    }
}

/**
 * Version asynchrone - lance le processus ls sans attendre
 */
pid_t execute_ls_command_async(void)
{
    pid_t ls_pid;
    
    KINFO("[INIT] Lancement asynchrone de la commande ls\n");
    
    /* Creer et lancer le processus ls */
    ls_pid = spawn_ls_process();
    if (ls_pid < 0) {
        KERROR("[INIT] echec du lancement du processus ls\n");
        return -1;
    }
    
    KINFO("[INIT] Processus ls lance en arriere-plan (PID %u)\n", ls_pid);
    return ls_pid;
}

/**
 * Fonction de test complete du systeme de processus avec ls
 */
void test_process_system_with_ls(void)
{
    kprintf("\n=== Test du systeme de processus avec commande ls ===\n");
    
    /* Verifications preliminaires */
    if (!current_task) {
        kprintf("KO Aucun processus courant\n");
        return;
    }
    
    kprintf("OK Processus courant: PID %u\n", current_task->process->pid);
    
    if (!is_fat32_mounted()) {
        kprintf("KO Systeme de fichiers non monte\n");
        return;
    }
    
    kprintf("OK Systeme de fichiers monte\n");
    
    /* Test 1: Execution synchrone */
    kprintf("\n--- Test 1: Execution synchrone ---\n");
    int result = execute_ls_command_sync();
    kprintf("Resultat de ls synchrone: %d\n", result);
    
    /* Petite pause */
    for (volatile int i = 0; i < 5000000; i++);
    
    /* Test 2: Execution asynchrone */
    kprintf("\n--- Test 2: Execution asynchrone ---\n");
    pid_t async_pid = execute_ls_command_async();
    kprintf("PID du ls asynchrone: %d\n", async_pid);
    
    /* Permettre au processus asynchrone de s'executer */
    schedule();
    
    kprintf("=== Fin des tests ===\n\n");
}



void test_ramfs_cluster_content(void)
{
    KINFO("[TEST] === Test contenu RAMFS cluster racine ===\n");

    extern void debug_memory_layout_ramfs(void);
    extern void debug_ramfs_creation_step_by_step(void);
    extern void ramfs_test(void);

    debug_memory_layout_ramfs();
    //debug_ramfs_creation_step_by_step();
    ramfs_tar_test();

    
    uint32_t root_cluster = get_fat32_root_cluster();
    uint32_t bytes_per_cluster = get_fat32_bytes_per_cluster();
    
    KINFO("[TEST] Cluster racine: %u\n", root_cluster);
    KINFO("[TEST] Bytes par cluster: %u\n", bytes_per_cluster);
    
    /* Calculer le secteur du cluster racine */
    uint32_t sector = cluster_to_sector(root_cluster);
    KINFO("[TEST] Secteur calcule: %u\n", sector);
    
    /* Lire directement avec RAMFS */
    static uint8_t direct_buffer[512];
    int result = ramfs_read_sectors(sector, 1, direct_buffer);
    
    KINFO("[TEST] ramfs_read_sectors resultat: %d\n", result);
    
    if (result > 0) {
        KINFO("[TEST] OK Lecture directe RAMFS reussie\n");
        
        KINFO("[TEST] Contenu brut du secteur:\n");
        for (int i = 0; i < 64; i += 16) {
            KINFO("[TEST] %04X: ", i);
            for (int j = 0; j < 16; j++) {
                kprintf("%02X ", direct_buffer[i + j]);
            }
            kprintf(" | ");
            for (int j = 0; j < 16; j++) {
                char c = direct_buffer[i + j];
                kprintf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
            kprintf("\n");
        }
        
        /* Analyser comme entrees FAT32 */
        fat32_dir_entry_t* entries = (fat32_dir_entry_t*)direct_buffer;
        
        KINFO("[TEST] Analyse comme entrees FAT32:\n");
        for (int i = 0; i < 4; i++) {
            fat32_dir_entry_t* entry = &entries[i];
            
            if (entry->name[0] == 0) {
                KINFO("[TEST] Entree %d: FIN\n", i);
                break;
            }
            
            KINFO("[TEST] Entree %d: name='%.11s', attr=0x%02X\n", 
                  i, entry->name, entry->attr);
        }
    } else {
        KERROR("[TEST] KO echec lecture directe RAMFS\n");
    }
}