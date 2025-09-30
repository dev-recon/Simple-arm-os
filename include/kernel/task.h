/* include/kernel/task.h - Systeme de taches pour ARM Cortex-A15 */
#ifndef _KERNEL_TASK_H
#define _KERNEL_TASK_H

#include <kernel/types.h>
#include <kernel/memory.h>
#include <kernel/spinlock.h>
#include <kernel/kernel.h>

struct signal_state_t;
struct file;

/* Configuration */
#define KERNEL_TASK_STACK_SIZE  (16 * 1024)    /* 16KB par tache */
#define MAX_TASKS               128              /* Maximum de taches */
#define TASK_NAME_MAX           32              /* Longueur max du nom */
#define MAX_SIGNALS             32

#define QUANTUM_TICKS           10

/* Forward declarations for structures */
typedef struct inode inode_t;
typedef struct file file_t;
typedef struct file_operations file_operations_t;
typedef struct inode_operations inode_operations_t;

/* Inode structure */
struct inode {
    uint32_t ino;
    uint16_t mode;
    uint16_t uid;
    uint16_t gid;
    uint32_t size;
    uint32_t atime;
    uint32_t mtime;
    uint32_t ctime;
    uint32_t blocks;
    uint32_t ref_count;
    
    /* Filesystem specific */
    uint32_t first_cluster;
    uint32_t parent_cluster;
    
    /* Operations */
    inode_operations_t* i_op;
    file_operations_t* f_op;
    
    struct inode* next;
};

/* File structure */
struct file {
    char name[256];               /* Nom du fichier */
    uint32_t pos;
    inode_t* inode;
    uint32_t offset;
    uint32_t flags;
    uint32_t ref_count;
    file_operations_t* f_op;
    void* private_data;
};

/* Directory entry */
typedef struct dirent {
    uint32_t d_ino;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[256];
} dirent_t;

/* File operations */
struct file_operations {
    ssize_t (*read)(file_t* file, void* buffer, size_t count);
    ssize_t (*write)(file_t* file, const void* buffer, size_t count);
    int (*open)(inode_t* inode, file_t* file);
    int (*close)(file_t* file);
    off_t (*lseek)(file_t* file, off_t offset, int whence);
    int (*readdir)(file_t* file, dirent_t* dirent);
};

/* Inode operations */
struct inode_operations {
    inode_t* (*lookup)(inode_t* dir, const char* name);
    int (*create)(inode_t* dir, const char* name, uint16_t mode);
    int (*mkdir)(inode_t* dir, const char* name, uint16_t mode);
    int (*unlink)(inode_t* dir, const char* name);
};

/* Stat structure */
struct stat {
    dev_t st_dev;
    ino_t st_ino;
    mode_t st_mode;
    nlink_t st_nlink;
    uid_t st_uid;
    gid_t st_gid;
    dev_t st_rdev;
    off_t st_size;
    blksize_t st_blksize;
    blkcnt_t st_blocks;
    time_t st_atime;
    time_t st_mtime;
    time_t st_ctime;
};

/* etats des taches */
typedef enum {
    TASK_READY = 0,         /* Prete a s'executer */
    TASK_RUNNING,           /* En cours d'execution */
    TASK_BLOCKED,           /* Bloquee (I/O, sleep, etc.) */
    TASK_ZOMBIE,            /* Terminee, en attente de nettoyage */
    TASK_TERMINATED         /* Completement terminee */
} task_state_t;

typedef enum {
    PROC_READY ,
    PROC_RUNNING,
    PROC_BLOCKED,
    PROC_ZOMBIE,
    PROC_DEAD
} proc_state_t;

typedef enum {
    TASK_TYPE_PROCESS = 1,  /* Processus principal */
    TASK_TYPE_THREAD = 2,   /* Thread dans un processus */
    TASK_TYPE_KERNEL = 3    /* Tache kernel pure */
} task_type_t;

/* Structure pour sauvegarder le contexte ARM32 */
typedef struct task_context {
    /* Registres generaux r0-r12 */
    uint32_t r0, r1, r2, r3, r4, r5, r6;
    uint32_t r7, r8, r9, r10, r11, r12;
    
    /* Registres speciaux */
    uint32_t sp;            // Stack Pointer 
    uint32_t lr;            // Link Register 
    uint32_t pc;            // Program Counter 
    uint32_t cpsr;          // Current Program Status Register 
    
    uint32_t is_first_run;  // NOUVEAU: Flag pour premiere execution 
    uint32_t ttbr0;
    uint32_t asid;

    uint32_t spsr;             // SPSR_svc 
    uint32_t returns_to_user;  // has to return to user mode 

    uint32_t usr_r[13];   // r0..r12 à l’entrée SVC (ou état prêt à repartir)
    uint32_t usr_sp;
    uint32_t usr_lr;      // optionnel si tu l’utilises
    uint32_t usr_pc;      // point de reprise user
    uint32_t usr_cpsr;    // en général 0x10
    uint32_t svc_sp_top;  // haut de pile noyau allouée pour ce task
    uint32_t svc_sp;      // courant (si tu le tiens à jour)
    uint32_t svc_lr_saved; // si tu en as besoin

} __attribute__((aligned(8))) task_context_t;


/* Signal actions */
typedef enum {
    SIG_ACT_TERM,
    SIG_ACT_IGN,
    SIG_ACT_CORE,
    SIG_ACT_STOP,
    SIG_ACT_CONT
} sig_default_action_t;

/* Signal handler */
typedef void (*sig_handler_t)(int);
#define SIG_DFL  ((sig_handler_t)0)
#define SIG_IGN  ((sig_handler_t)1)

/* Sigaction structure */
typedef struct {
    sig_handler_t sa_handler;
    uint32_t sa_mask;
    int sa_flags;
} sigaction_t;

/* Signal state */
typedef struct {
    sigaction_t actions[MAX_SIGNALS];
    uint32_t pending;
    uint32_t blocked;
    uint32_t in_handler;
    
    task_context_t saved_context;
} signal_state_t;

typedef struct {
    pid_t pid;              /* PID POSIX */
    pid_t ppid;             /* Parent PID */
    struct task* parent;    /* Processus parent */
    struct task* children;  /* Enfants */
    struct task* sibling_next;
    vm_space_t* vm;         /* Espace memoire */
    file_t* files[MAX_FILES];  /* Descripteurs */
    int exit_code;
    uid_t uid, gid;

    proc_state_t state;

        /* Signals */
    signal_state_t signals;
    
    /* Signal stack */
    uint32_t signal_stack_base;
    uint32_t signal_stack_size;

    /* === AJOUT : Contexte waitpid === */
    /* Ces champs permettent de sauvegarder le contexte lors d'un blocage dans waitpid */
    pid_t waitpid_pid;          /* PID attendu dans waitpid */
    int* waitpid_status;        /* Pointeur status dans waitpid */
    int waitpid_options;        /* Options waitpid */
    int waitpid_iteration;      /* Numero d'iteration dans waitpid */
    uint32_t waitpid_caller_lr; /* LR pour retourner apres waitpid */

    char cwd[MAX_PATH];   /* Current Working Directory */

} __attribute__((aligned(8))) process_t;


/* Structure d'une tache */
typedef struct task {
    /* Identification */
    uint32_t task_id;                       /* ID unique */
    char name[TASK_NAME_MAX];               /* Nom de la tache */
    task_state_t state;                     /* etat actuel */
    uint32_t priority;                      /* Priorite (0 = plus haute) */
    
    /* Contexte et stack */
    task_context_t context;                 /* Contexte sauvegarde */
    void* stack_base;                       /* Base de la stack */
    void* stack_top;                        /* Sommet de la stack */
    uint32_t stack_size;                    /* Taille de la stack */
    
    /* Fonction d'entree */
    void (*entry_point)(void* arg);         /* Point d'entree */
    void* entry_arg;                        /* Argument */
    
    /* Liste chainee */
    struct task* next;                      /* Tache suivante */
    struct task* prev;                      /* Tache precedente */
    
    /* Statistiques */
    uint64_t created_time;                  /* Timestamp de creation */
    uint64_t total_runtime;                 /* Temps total d'execution */
    uint32_t switch_count;                  /* Nombre de commutations */
    
    /* === EXTENSIONS PROCESSUS === */
    task_type_t type;               /* Type de tache */
    uint32_t quantum_left;
    volatile uint8_t defer_return_to_user; /* 0/1 */
    
    /* Donnees processus (seulement si type == PROCESS) */
    union {
        process_t* process;
        struct {
            struct task* process;   /* Processus proprietaire */
            void* thread_data;      /* Donnees thread */
        } thread;
    };

} __attribute__((aligned(8))) task_t;

/* Interface publique */
uid_t current_uid(void);
uid_t current_gid(void);

/* Initialisation du systeme */
void init_task_system(void);
void cleanup_task_system(void);

/* Creation et destruction */
task_t* task_create(const char* name, void (*entry)(void* arg), void* arg, uint32_t priority);
task_t* task_create_process(const char* name, void (*entry)(void* arg), void* arg, uint32_t priority, task_type_t type);
void task_destroy(task_t* task);

/* Gestion du scheduler */
void yield(void);                           /* Ceder le CPU volontairement */
void schedule(void);                        /* Forcer une commutation */
void sched_start(void);                     /* Demarrer le scheduler */
void task_sleep_ms(uint32_t ms);
void schedule_to(task_t *next_task);

/* Acces aux taches */
task_t* task_find_by_id(uint32_t task_id);  /* Trouver par ID */
task_t* task_find_by_name(const char* name); /* Trouver par nom */
void setup_task_context(task_t* task);
void add_to_ready_queue(task_t* task);
void remove_from_ready_queue(task_t* task);
void destroy_zombie_process(task_t* zombie);
bool is_in_ready_queue(task_t* task);

/* Gestion des priorites */
void task_set_priority(task_t* task, uint32_t priority);
uint32_t task_get_priority(task_t* task);

/* etats des taches */
void task_set_state(task_t* task, task_state_t state);
task_state_t task_get_state(task_t* task);
const char* task_state_string(task_state_t state);
const char* proc_state_string(proc_state_t state);

/* Utilitaires de debug */
void task_dump_info(task_t* task);          /* Infos d'une tache */
void task_list_all(void);                   /* Liste toutes les taches */
void task_dump_stacks(void);                /* Analyse des stacks */
void task_check_stack_integrity(void);      /* Verification integrite */
void debug_current_task_detailed(const char* location);
void task_dump_stacks_detailed(void);                /* Analyse des stacks */
void debug_all_task_stacks(void);
void debug_print_ctx(task_context_t *context, const char* caller);


/* Statistiques */
uint32_t task_get_count(void);              /* Nombre de taches */
void task_print_stats(void);                /* Statistiques globales */

/* Fonctions internes de commutation (assembleur) */
void __task_first_switch_v2(task_context_t* new_ctx);
void __task_switch_asm(task_context_t* old_ctx, task_context_t* new_ctx);
void __task_switch(task_context_t* old_ctx, task_context_t* new_ctx);
void switch_to_idle(void);

extern task_t* current_task;
extern task_t* task_list_head;
extern uint32_t task_count;
extern spinlock_t task_lock;
extern task_t* idle_task;
extern task_t* init_process;


void add_task_to_list(task_t* task);

extern void get_and_save_usr_context(task_t* t);
/* ↑ Petite routine appelée à l’entrée SVC pour remplir :
     t->context.usr_pc   = LR_svc (PC de retour user)
     t->context.usr_cpsr = SPSR_svc (donc 0x10 typiquement)
     t->context.usr_sp   = SP_usr   (via cps #SYS puis mov)
     t->context.usr_r[i] = r0..r12 user (cf. wrapper SVC)
*/

#define TASK_CONTEXT_OFF = offsetof(task_t, context);

/* Ajout des fonctions de gestion des interruptions ARM */
static inline uint32_t disable_interrupts_save(void)
{
    uint32_t cpsr;
    __asm__ volatile(
        "mrs %0, cpsr\n"      /* Lire CPSR actuel */
        "cpsid if"            /* Desactiver IRQ et FIQ */
        : "=r" (cpsr)
        :
        : "memory"
    );
    return cpsr;
}

static inline void restore_interrupts(uint32_t cpsr)
{
    __asm__ volatile(
        "msr cpsr_c, %0"      /* Restaurer seulement les bits de controle */
        :
        : "r" (cpsr)
        : "memory"
    );
}

#endif /* _KERNEL_TASK_H */