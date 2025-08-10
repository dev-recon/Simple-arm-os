/* kernel/task/task_test.c - Tests du systeme de taches */
#include <kernel/task.h>
#include <kernel/kernel.h>
#include <kernel/kprintf.h>
#include <kernel/string.h>
#include <kernel/process.h>

/* Fonctions de test */
static void test_task_a(void* arg);
static void test_task_b(void* arg);
static void test_task_c(void* arg);
static void counter_task(void* arg);

/* Variables partagees pour les tests */
static volatile uint32_t shared_counter = 0;
static volatile uint32_t task_a_count = 0;
static volatile uint32_t task_b_count = 0;
static volatile uint32_t task_c_count = 0;

void test_task_system(void)
{
    task_t* task_a;
    task_t* task_b;
    task_t* task_c;
    task_t* counter;
    int i;
    
    KINFO("=== TESTING TASK SYSTEM ===\n");
    
    /* Verifier que le systeme est initialise */
    if (!current_task) {
        KERROR("Task system not initialized!\n");
        return;
    }
    
    KINFO("Current task: %s\n", ((task_t*)current_task)->name);
    task_list_all();
    
    /* Test 1: Creer quelques taches simples */
    KINFO("\n--- Test 1: Creating tasks ---\n");
    
    task_a = task_create("task_a", test_task_a, (void*)1, 10);
    task_b = task_create("task_b", test_task_b, (void*)2, 20);
    task_c = task_create("task_c", test_task_c, (void*)3, 30);
    counter = task_create("counter", counter_task, NULL, 5);
    
    if (!task_a || !task_b || !task_c || !counter) {
        KERROR("Failed to create test tasks\n");
        return;
    }
    
    KINFO("Created all test tasks successfully\n");
    task_list_all();
    
    /* Test 2: Laisser les taches tourner un peu */
    KINFO("\n--- Test 2: Running tasks ---\n");
    KINFO("Letting tasks run for a few cycles...\n");
    
    for (i = 0; i < 10; i++) {
        KINFO("Main loop iteration %d\n", i);
        yield();  /* Donner une chance aux autres taches */
        
        /* Afficher les statistiques */
        if (i % 3 == 0) {
            KINFO("Stats: A=%u, B=%u, C=%u, Counter=%u\n", 
                  task_a_count, task_b_count, task_c_count, shared_counter);
        }
    }
    
    /* Test 3: Tester les priorites */
    KINFO("\n--- Test 3: Priority test ---\n");
    KINFO("Changing task priorities...\n");
    
    task_set_priority(task_c, 1);  /* task_c devient prioritaire */
    
    for (i = 0; i < 5; i++) {
        KINFO("Priority test iteration %d\n", i);
        yield();
    }
    
    KINFO("Final stats: A=%u, B=%u, C=%u, Counter=%u\n", 
          task_a_count, task_b_count, task_c_count, shared_counter);
    
    /* Test 4: Information detaillee sur les taches */
    KINFO("\n--- Test 4: Task details ---\n");
    task_dump_info(task_a);
    task_dump_info(current_task);
    
    task_list_all();
    
    KINFO("\n=== TASK SYSTEM TESTS COMPLETED ===\n");
    
    /* Les taches continuent de tourner... */
    KINFO("Tasks will continue running. Use task_destroy() to clean up.\n");
}

static void test_task_a(void* arg)
{
    uint32_t my_id = (uint32_t)arg;
    uint32_t local_count = 0;
    
    KINFO("Task A started with arg=%u\n", my_id);
    
    while (1) {
        local_count++;
        task_a_count++;
        
        if (local_count % 5 == 0) {
            KINFO("Task A: iteration %u (total=%u)\n", local_count, task_a_count);
        }
        
        /* Faire quelque chose d'utile */
        shared_counter += 1;
        
        /* Ceder le processeur */
        yield();
        
        /* Limiter pour eviter de spammer */
        if (local_count > 50) {
            KINFO("Task A: completed 50 iterations, exiting\n");
            break;
        }
    }
    
    KINFO("Task A finished\n");
    /* La tache se termine, task_destroy sera appele automatiquement via LR */
}

static void test_task_b(void* arg)
{
    uint32_t my_id = (uint32_t)arg;
    uint32_t local_count = 0;
    
    KINFO("Task B started with arg=%u\n", my_id);
    
    while (1) {
        local_count++;
        task_b_count++;
        
        if (local_count % 7 == 0) {
            KINFO("Task B: iteration %u (total=%u)\n", local_count, task_b_count);
        }
        
        /* Faire quelque chose de different */
        shared_counter += 2;
        
        /* Ceder le processeur */
        yield();
        
        /* Cette tache tourne plus longtemps */
        if (local_count > 30) {
            KINFO("Task B: completed 30 iterations, exiting\n");
            break;
        }
    }
    
    KINFO("Task B finished\n");
}

static void test_task_c(void* arg)
{
    uint32_t my_id = (uint32_t)arg;
    uint32_t local_count = 0;
    
    KINFO("Task C started with arg=%u\n", my_id);
    
    while (1) {
        local_count++;
        task_c_count++;
        
        if (local_count % 3 == 0) {
            KINFO("Task C: iteration %u (total=%u) [HIGH PRIORITY]\n", 
                  local_count, task_c_count);
        }
        
        /* Incrementer le compteur partage */
        shared_counter += 5;
        
        yield();
        
        if (local_count > 20) {
            KINFO("Task C: completed 20 iterations, exiting\n");
            break;
        }
    }
    
    KINFO("Task C finished\n");
}

static void counter_task(void* arg)
{
    uint32_t local_count = 0;
    uint32_t last_shared = 0;
    
    (void)arg;  /* Pas d'argument utilise */
    
    KINFO("Counter task started\n");
    
    while (1) {
        local_count++;
        
        /* Afficher les stats periodiquement */
        if (local_count % 10 == 0) {
            uint32_t current_shared = shared_counter;
            uint32_t delta = current_shared - last_shared;
            
            KINFO("COUNTER: Local=%u, Shared=%u (+%u), Tasks: A=%u B=%u C=%u\n",
                  local_count, current_shared, delta,
                  task_a_count, task_b_count, task_c_count);
            
            last_shared = current_shared;
        }
        
        yield();
        
        /* Cette tache tourne indefiniment */
    }
}

/* Test simple pour verifier les fonctions de base */
void test_basic_task_functions(void)
{
    task_t* current;
    
    KINFO("=== BASIC TASK FUNCTION TESTS ===\n");
    
    /* Test 1: get_current_task */
    current = current_task;
    if (current) {
        KINFO("OK current_task: %s (ID=%u)\n", current->name, current->task_id);
    } else {
        KERROR("KO current_task returned NULL\n");
        return;
    }
    
    /* Test 2: task_dump_info */
    KINFO("OK Dumping current task info:\n");
    task_dump_info(current);
    
    /* Test 3: task_list_all */
    KINFO("OK Listing all tasks:\n");
    task_list_all();
    
    /* Test 4: yield */
    KINFO("OK Testing yield():\n");
    KINFO("Before yield\n");
    yield();
    KINFO("After yield\n");
    
    KINFO("=== BASIC TESTS COMPLETED ===\n");
}

/* Test de stress pour la commutation */
void test_task_stress(void)
{
    task_t* stress_tasks[5];
    int i;
    
    KINFO("=== STRESS TEST ===\n");
    
    /* Creer plusieurs taches identiques */
    for (i = 0; i < 5; i++) {
        char name[32];
        snprintf(name, sizeof(name), "stress_%d", i);
        
        stress_tasks[i] = task_create(name, counter_task, (void*)(uintptr_t)i, 50 + i);
        
        if (!stress_tasks[i]) {
            KERROR("Failed to create stress task %d\n", i);
            return;
        }
    }
    
    KINFO("Created 5 stress tasks\n");
    task_list_all();
    
    /* Laisser tourner */
    for (i = 0; i < 100; i++) {
        if (i % 20 == 0) {
            KINFO("Stress test iteration %d/100\n", i);
        }
        yield();
    }
    
    KINFO("Stress test completed\n");
    
    /* Note: On ne nettoie pas les taches pour voir si elles continuent de tourner */
}