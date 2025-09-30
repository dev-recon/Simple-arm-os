/* kernel/task/kernel_tasks.c - Taches systeme du kernel */
#include <kernel/kernel_tasks.h>
#include <kernel/task.h>
#include <kernel/memory.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>
#include <kernel/syscalls.h>
#include <kernel/process.h>
#include <kernel/timer.h>
#include <kernel/file.h>

/* === VARIABLES STATIQUES === */
static volatile bool system_shutdown = false;
extern void __task_switch_asm_debug(task_context_t* old_ctx, task_context_t* new_ctx);
void robust_test_func(void* arg);
void robust_test_func_v2(void* arg);
extern int ls_read_directory(const char* path);

#define SLEEP_TIME 100000

static int fork_depth = 0;

/* === FONCTIONS PUBLIQUES === */

void kernel_main_loop(void)
{
    uint32_t loop_count = 0;
    
    KINFO("Entering kernel main loop...\n");
    
    while (!system_shutdown) {
        loop_count++;
        
        /* Affichage periodique */
        if (loop_count % 1000 == 0) {
            KINFO("Kernel main loop: iteration %u\n", loop_count);
            
            /* Afficher les stats memoire */
            if (loop_count % 5000 == 0) {
                print_memory_stats();
            }
        }
        
        /* Ceder le processeur aux autres taches */
        yield();
        
        /* Votre code de gestion d'evenements ici */
        /* handle_interrupts(); */
        /* process_network_packets(); */
        /* etc. */
    }
    
    KINFO("Kernel main loop terminated\n");
}

void create_system_tasks(void)
{
    task_t* sysmon_task;
    task_t* memtest_task;
    task_t* shell_task2;
    
    KINFO("Creating system tasks...\n");
    
    /* Tache de monitoring systeme */
    sysmon_task = task_create("sysmon", system_monitor_task, NULL, 10);
    if (!sysmon_task) {
        KERROR("Failed to create system monitor task\n");
        return;
    }
    
    /* Tache de test memoire */
    memtest_task = task_create("memtest", memory_test_task, NULL, 20);
    if (!memtest_task) {
        KERROR("Failed to create memory test task\n");
        return;
    }
    
    /* Tache shell simple */
    shell_task2 = task_create("shell2", simple_shell_task2, NULL, 15);
    if (!shell_task2) {
        KERROR("Failed to create shell2 task\n");
        return;
    }

    add_to_ready_queue(sysmon_task);
    add_to_ready_queue(memtest_task);
    add_to_ready_queue(shell_task2);
    
    KINFO("System tasks created successfully:\n");
    KINFO("  - System Monitor (priority 10)\n");
    KINFO("  - Memory Test (priority 20)\n");
    KINFO("  - Simple Shell (priority 15)\n");
}

void shutdown_task_system(void)
{
    KINFO("Shutting down task system...\n");
    
    /* Marquer le systeme pour arret */
    system_shutdown = true;
    
    /* Ici vous pourriez implementer:
     * - Arret propre des taches
     * - Nettoyage des ressources
     * - Sauvegarde d'etat si necessaire
     */
    
    KINFO("Task system shutdown completed\n");
}

/* === TaCHES SYSTeME === */

void system_monitor_task(void* arg)
{
        // PREMIeRE LIGNE - tres important !
    KINFO("=== SYSMON STARTED SUCCESSFULLY ===\n");
    uint32_t iterations = 0;
    
    (void)arg;
    
    /* Verification de la stack des le debut */
    uint32_t current_sp;
    __asm__ volatile("mov %0, sp" : "=r"(current_sp));
    //KINFO("System monitor task started, SP=0x%08X\n", current_sp);
    
    /* Test d'acces memoire de base */
    volatile uint32_t test_var = 0x12345678;
    if (test_var != 0x12345678) {
        KERROR("[SYSMON] Memory test failed!\n");
        return;
    }
    //KDEBUG("[SYSMON] Memory test OK\n");
    
    while (!system_shutdown) {
        iterations++;
        
        /* Test d'acces memoire a chaque iteration */
        test_var = iterations;
        
        /* Monitoring periodique */
        if (iterations % 50 == 0) {
            //task_t* current = current_task;
            //KINFO("[SYSMON] Current task: %s, Iteration: %u\n", 
            //      current ? current->name : "unknown", iterations);
            
            /* Afficher les stats systeme */
            if (iterations % 200 == 0) {
                KINFO("[SYSMON] === System Status ===\n");
                print_system_stats();
                KINFO("[SYSMON] ==================\n");
            }

        
        }

        task_sleep_ms(SLEEP_TIME/1000);
        yield();
    }
    
    KINFO("System monitor task terminated\n");
}

void memory_test_task(void* arg)
{
    void* test_ptrs[10];
    int i;
    uint32_t test_count = 0;
    
    (void)arg;
    KINFO("Memory test task started %d\n", system_shutdown );
    
    while (!system_shutdown) {
        test_count++;
        
        /* Test d'allocation/liberation */        
        /* Allouer quelques blocs */
        for (i = 0; i < 10; i++) {
            test_ptrs[i] = kmalloc(64 + i * 16);
            if (!test_ptrs[i]) {
                KERROR("[MEMTEST] Failed to allocate block %d\n", i);
                break;
            }
        }
        
        /* Liberer les blocs */
        for (i = 0; i < 10; i++) {
            if (test_ptrs[i]) {
                kfree(test_ptrs[i]);
                test_ptrs[i] = NULL;
            }
        }

        KINFO("[MEMTEST] Tests de memoire OK\n");
        
        /* Test moins frequent */
        if (test_count % 10 == 0) {
            KINFO("[MEMTEST] Completed %u memory test cycles\n", test_count);
        }
        
        task_sleep_ms(SLEEP_TIME);
        yield();

        
        /* Ralentir un peu les tests */
        task_sleep_ms(SLEEP_TIME);
    }
    
    KINFO("Memory test task terminated\n");
}

void simple_shell_task2(void* arg)
{
    uint32_t cmd_count = 0;
    
    (void)arg;
    KINFO("Simple shell task started\n");
    KINFO("Type 'help' for available commands\n");
    
    while (!system_shutdown) {
        cmd_count++;

        shell_process_command("ps");
        //system_shutdown = true;

        /* Simuler la reception d'une commande */
        if (cmd_count % 100 == 0) {
            KINFO("[SHELL] Ready for command (simulation %u)\n", cmd_count);
            
            /* Simuler quelques commandes */
            switch ((cmd_count / 100) % 4) {
                case 0:
                    shell_process_command("ps");
                    break;
                case 1:
                    shell_process_command("mem");
                    break;
                case 2:
                    shell_process_command("tasks");
                    break;
                case 3:
                    shell_process_command("help");
                    break;
            }
        }
        
        task_sleep_ms(SLEEP_TIME);
        yield();
    }
    
    KINFO("Simple shell task terminated\n");
}

/* === FONCTIONS UTILITAIRES === */

void shell_process_command(const char* cmd)
{
    if (!cmd) return;
    
    KINFO("[SHELL] Processing command: %s\n", cmd);
    
    if (strcmp(cmd, "ps") == 0 || strcmp(cmd, "tasks") == 0) {
        task_list_all();
    }
    else if (strcmp(cmd, "mem") == 0) {
        print_memory_stats();
    }
    else if (strcmp(cmd, "stats") == 0) {
        print_system_stats();
    }
    else if (strcmp(cmd, "help") == 0) {
        KINFO("Available commands:\n");
        KINFO("  ps, tasks - List all tasks\n");
        KINFO("  mem       - Show memory status\n");
        KINFO("  stats     - Show system statistics\n");
        KINFO("  help      - Show this help\n");
    }
    else if (strcmp(cmd, "shutdown") == 0) {
        KINFO("Initiating system shutdown...\n");
        shutdown_task_system();
    }
    else {
        KINFO("Unknown command: %s (type 'help' for available commands)\n", cmd);
    }
}

void print_system_stats(void)
{
    task_t* current = current_task;
    
    KINFO("=== System Statistics ===\n");
    KINFO("Current task: %s\n", current ? current->name : "unknown");
    
    print_memory_stats();
    
    KINFO("Task list:\n");
    task_list_all();
    
    KINFO("=========================\n");
}

void print_memory_stats(void)
{
    uint32_t free_pages = get_free_page_count();
    uint32_t total_pages = get_total_page_count();
    uint32_t used_pages = total_pages - free_pages;
    
    KINFO("Memory status:\n");
    KINFO("  Total pages: %u (%u MB)\n", 
          total_pages, (total_pages * PAGE_SIZE) / (1024 * 1024));
    KINFO("  Used pages:  %u (%u MB)\n", 
          used_pages, (used_pages * PAGE_SIZE) / (1024 * 1024));
    KINFO("  Free pages:  %u (%u MB)\n", 
          free_pages, (free_pages * PAGE_SIZE) / (1024 * 1024));
    KINFO("  Usage:       %u%%\n", 
          total_pages > 0 ? (used_pages * 100) / total_pages : 0);
    
    KINFO("Heap statistics:\n");
    kheap_stats();
}



/*======================= TESTS ============================*/

/* Test minimal avec la version debug */
void test_context_switch_minimal(void)
{
    KINFO("=== MINIMAL CONTEXT SWITCH TEST ===\n");
    
    /* Creer UNE SEULE tache de test */
    task_t* test_task = task_create("minimal_test", minimal_test_func, NULL, 10);
    
    if (!test_task) {
        KERROR("Failed to create test task\n");
        return;
    }
    
    KINFO("Test task created, starting debug scheduler...\n");
    
    /* Appeler le scheduler debug une fois */
    schedule();
    
    KINFO("First schedule call completed\n");
    
    /* Laisser la tache tourner un peu */
    for (int i = 0; i < 5; i++) {
        KINFO("Main: iteration %d\n", i);
        schedule();
    }
    
    KINFO("=== MINIMAL TEST COMPLETED ===\n");
}

void minimal_test_func(void* arg)
{
    (void)arg;

    KINFO("- MINIMAL TEST TASK STARTED!\n");
    
    for (int i = 0; i < 3; i++) {
        KINFO("- Test task iteration %d\n", i);
        
        /* Test de l'integrite de la stack */
        uint32_t current_sp;
        __asm__ volatile("mov %0, sp" : "=r"(current_sp));
        KINFO("- Current SP in task: 0x%08X\n", current_sp);
        
        /* Variable locale pour tester la stack */
        volatile uint32_t test_var = 0x12345678u + i;
        if (test_var != (0x12345678u + i)) {
            KERROR("- STACK CORRUPTION DETECTED!\n");
            break;
        }
        
        KINFO("- About to yield...\n");
        yield();
        KINFO("- Returned from yield - CONTEXT SWITCH WORKED!\n");
    }
    
    KINFO("- MINIMAL TEST TASK FINISHED\n");
}

/* Version encore plus simple pour identifier le probleme exact */
void ultra_simple_test(void)
{
    KINFO("=== ULTRA SIMPLE TEST ===\n");
    //task_dump_stacks_detailed();
    
    /* Afficher l'etat actuel */
    task_t* current = current_task;
    KINFO("Current task: %s\n", current ? current->name : "NULL");
    KINFO("Current SP: 0x%08X\n", current ? current->context.sp : 0);
    //task_dump_stacks_detailed();
    
    /* Creer une tache qui ne fait rien */
    //task_t* simple = task_create("ultra_simple", ultra_simple_func, NULL, 50);
    task_t* simple = task_create_process("ultra_simple", ultra_simple_func, NULL, 50, TASK_TYPE_PROCESS);
    //task_dump_stacks_detailed();
    
    if (!simple) {
        KERROR("Failed to create ultra simple task\n");
        return;
    }
    
    KINFO("Ultra simple task created\n");
    KINFO("About to call schedule for the first time...\n");

    //task_dump_stacks_detailed();
    
    /* Premier appel critique */
    schedule();
    
    KINFO("Returned from first schedule - SUCCESS!\n");
}

void ultra_simple_func(void* arg)
{
    (void) arg;
    //task_t* current = current_task;

    //task_dump_info(current);
    //task_dump_stacks_detailed();

    KINFO("- ULTRA SIMPLE TASK: Hello World!\n");
    KINFO("- ULTRA SIMPLE TASK: Goodbye!\n");


    //task_dump_info(current);
    //task_dump_stacks_detailed();

    //yield();
    task_destroy(NULL);  // Detruire la tache courante
    
    // Ne devrait jamais arriver ici
    while(1) __asm__ volatile("wfe");
    /* Terminaison immediate */
}




/**
 * Lister tous les processus - CORRIGe
 */
void list_all_processes(void)
{
    task_t* task = task_list_head;
    int count = 0;
    
    KINFO("=== Process List ===\n");
    
    if (!task_list_head) {
        KINFO("No processes\n");
        return;
    }
    
    spin_lock(&task_lock);
    
    do {
        if (task->type == TASK_TYPE_PROCESS) {
            /* ACCeS CORRECT */
            KINFO("PID=%u PPID=%u %s (state=%s proc_state=%s)\n",
                  task->process->pid,
                  task->process->ppid,
                  task->name,
                  task_state_string(task->state),
                  proc_state_string(task->process->state));
        } else {
            KINFO("TID=%u %s (type=%d, state=%s)\n",
                  task->task_id,
                  task->name,
                  task->type,
                  task_state_string(task->state));
        }
        
        task = task->next;
        count++;
    } while (task != task_list_head && count < MAX_TASKS);
    
    spin_unlock(&task_lock);
    
    KINFO("Total: %d tasks/processes\n", count);
}



/* Version corrigée de working_child avec debug */
void working_child(int level, int dummy) {
    
    volatile int saved_level = level;
    int local_level = saved_level;  // Force une copie


    /* DEBUG: État initial */
    //debug_working_child_state(level, "ENTRY");

    KINFO("[DEBUG] working_child called with level=%d\n", local_level);

    task_sleep_ms(10000);
    yield();

    /* DEBUG: Après sleep */
    //debug_working_child_state(local_level, "AFTER_SLEEP");

    static int status = 42; // Status de base
    
    /* DEBUG: Avant fork */
    //debug_working_child_state(local_level, "BEFORE_FORK");

    //local_level = fork_depth ;
    
    pid_t child_pid = sys_fork();
    
    /* DEBUG: Après fork */
    //debug_working_child_state(local_level, "AFTER_FORK");
    
    if (child_pid == 0) {
        /* Processus enfant */
        //debug_working_child_state(local_level, "CHILD_START");

        int local_variable = 32768 ;
        
        KINFO("[CHILD %d] *** CHILD PROCESS STARTED ***\n", ++fork_depth);
        KINFO("[CHILD %d] Hello from child! PID=%u PPID=%u\n", fork_depth,
                sys_getpid(), sys_getppid());
            
        
        /* L'enfant fait du travail */
        for (int i = 1; i <= 3; i++) {
            KINFO("[CHILD %d] Working... %d/3\n", fork_depth, i);
            KINFO("[CHILD %d] Printing local variable ... %d\n", fork_depth, local_variable++);

            task_sleep_ms(500);
            //yield();
        }

        /* Condition pour fork imbriqué */
        if (fork_depth < 5) {
            working_child(fork_depth+1,dummy);
        }
        
        KINFO("[CHILD %d] Exiting with code %d\n", fork_depth, status + fork_depth);
        KINFO("[CHILD %d] *** ABOUT TO EXIT ***\n", fork_depth);
        sys_exit(status + fork_depth);
        KERROR("[CHILD %d] ERROR: Code after sys_exit!\n", fork_depth);
        
    } else if (child_pid > 0) {
        /* Processus parent */
        //debug_working_child_state(local_level, "PARENT_CONTINUE");
        
        KINFO("[PARENT %d] Created child PID=%u\n", level, child_pid);
        KINFO("[PARENT %d] *** PARENT ABOUT TO WAIT ***\n", level);
        
        /* Attendre l'enfant */
        int wait_status;
        pid_t waited_pid = kernel_waitpid(child_pid, &wait_status, 0, current_task);
        
        KINFO("[PARENT %d] *** PARENT WOKE UP ***\n", level);
        KINFO("[PARENT %d] Child PID=%d exited with status=%d (hex 0x%08X)\n", level,
                waited_pid, wait_status, wait_status);

        //debug_print_ctx( &current_task->context);
        
        if (level > 1) {
            sys_exit(55 + level);
        }
        
    } else {
        KERROR("[PARENT %d] Fork failed: %d\n", level, child_pid);
    }
}


void mini_shell_READ(const char* path) {
    
    int len = strlen(path);
    char *kernel_path = (char *)kmalloc(len+1);
    strcpy(kernel_path, path);
    int fd = kernel_open(kernel_path, O_RDONLY , S_IRUSR);

    KDEBUG("AFTER SYS_OPEN fd = %d for filepath = %s\n", fd, path);

    if(fd>0)
    {
        uint8_t* buf = (uint8_t*)kmalloc(PAGE_SIZE);
        if(sys_read(fd, buf, PAGE_SIZE ))
        {
            hexdump((void *)buf, 128);
        }

        sys_close(fd);
    }

}

void mini_shell_CREATE(const char* path) {
    
    int len = strlen(path);
    char *kernel_path = (char *)kmalloc(len+1);
    strcpy(kernel_path, path);
    int fd = kernel_open(kernel_path, O_CREAT , S_IRUSR);

    const char* text = "Ceci est un petit texte de demonstration ...\n# Commentaires !!!\n";

    KDEBUG("AFTER SYS_OPEN fd = %d for filepath = %s\n", fd, path);

    if(fd>0)
    {
        sys_write(fd, (void*)text, strlen(text) );

        sys_close(fd);

        KDEBUG("AFTER sys_write fd = %d for filepath = %s\n", fd, path);

    }

}



void simple_shell_task3(void* arg) {

    (void)arg;

    //const char* path = "/readme.txt";
    const char* path2 = "/test.txt";

    task_sleep_ms(10000); 
    yield();

    kprintf("Parent PID: %d about to run program\n", sys_getpid());

    //mini_shell_CREATE(path2);
        
    //mini_shell_READ(path);

    //mini_shell_READ("/makefile");

    //mini_shell_READ("/home/user/profile.txt");

    //mini_shell_READ(path);



    //mini_shell_CREATE(path2);

    mini_shell_READ(path2);

    sys_exit(-1);
}

void simple_shell_task(void* arg) {

    (void)arg;

    const char* path = "/bin/hello";
    char* name = "hello";

    //task_sleep_ms(10000); 
    //yield();

    kprintf("Parent PID: %d about to exec\n", sys_getpid());
        
    char* const argv[] = { name, NULL };
    char* const envp[] = { NULL };

    //debug_all_task_stacks();
        
    int result = sys_execve(path , argv, envp);
        
    // Si on arrive ici, exec a échoué
    kprintf("Child: exec failed with %d\n", result);
    sys_exit(-1);
}


/**
 * Fonction shell simple pour tester les syscalls - adaptee
 */
void simple_shell_task4(void* arg)
{
    (void)arg;
    
    KINFO("=== SHELL STARTED ===\n");
    KINFO("Shell PID=%u, PPID=%u\n", 
          (current_task && current_task->type == TASK_TYPE_PROCESS) ? 
          current_task->process->pid : 0,
          (current_task && current_task->type == TASK_TYPE_PROCESS) ? 
          current_task->process->ppid : 0);
    
    int iteration = 0;
    
    while (iteration < 2) {
        iteration++;
        
        KINFO("[SHELL] Command %d> ", iteration);
        
        switch (iteration % 4) {
            case 1:
                KINFO("ps\n");
                list_all_processes();

                break;
                
            case 2:
                KINFO("fork-test\n");
                {

                    working_child(1,0);
 #if(0)
                    pid_t child_pid = sys_fork();
                    
                    if (child_pid == 0) {
                        /* Processus enfant */
                        KINFO("[CHILD] *** CHILD PROCESS STARTED ***\n");
                        KINFO("[CHILD] Hello from child! PID=%u PPID=%u\n", 
                              sys_getpid(), sys_getppid());
                        
                        /* L'enfant fait du travail */
                        for (int i = 1; i <= 3; i++) {
                            KINFO("[CHILD] Working... %d/3\n", i);
                            task_sleep_ms(500);
                            yield();
                        }


                        
                        KINFO("[CHILD] Exiting with code 42\n");
                        KINFO("[CHILD] *** ABOUT TO EXIT ***\n");
                        sys_exit(42);
                        KERROR("[CHILD] ERROR: Code after sys_exit!\n");
                        
                    } else if (child_pid > 0) {
                        /* Processus parent */
                        KINFO("[SHELL] Created child PID=%u\n", child_pid);
                        KINFO("[SHELL] *** PARENT ABOUT TO WAIT ***\n");
                        
                        /* Attendre l'enfant */
                        int status;
                        pid_t waited_pid = kernel_waitpid(child_pid, &status, 0);
                        
                        KINFO("[SHELL] *** PARENT WOKE UP ***\n");
                        KINFO("[SHELL] Child PID=%u exited with status=%d\n", 
                              waited_pid, status);
                        
                    } else {
                        KERROR("[SHELL] Fork failed: %d\n", child_pid);
                    }
#endif
                }
                break;
                
            case 3:
                KINFO("help\n");
                KINFO("[SHELL] Available commands: ps, fork-test, help, uptime\n");
                //create_system_tasks();
                break;
                
            case 0:
                KINFO("uptime\n");
                KINFO("[SHELL] System uptime: %u ticks\n", get_system_ticks());
                break;
        }
        
        /* Pause entre les commandes */
        task_sleep_ms(2000);

        //KDEBUG("SYSTEM TICKS = %d\n", get_system_ticks() ) ;
        //yield();
    }
    
    KINFO("[SHELL] Shell exiting\n");
    sys_exit(0);
    KERROR("[SHELL] ERROR: Code after sys_exit() executed!\n");
}
