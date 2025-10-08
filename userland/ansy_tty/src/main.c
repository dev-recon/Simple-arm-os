#include <ansi_tty.h>
#include <stdio.h>

int main(void) {
    tty_clear_screen();
    tty_set_title("Mon App User");
    tty_cursor_hide();

    tty_cursor_pos(2,2);
    tty_sgr_bold();
    tty_fg_basic(3); /* jaune */
    tty_puts("Hello "); 
    tty_fg_256(82);  /* un vert 256 */
    tty_puts("World");
    tty_sgr_reset();

    tty_cursor_pos(4,2);
    tty_puts("Progress: ");
    for (int i=0;i<=20;i++) {
        tty_cursor_pos(4,12);
        char percent[4];
        int p = i*5;
        /* print number quickly via tty_puts + small dec conversion */
        char tmp[8]; int q = append_uint(tmp, p); tmp[q]=0;
        tty_puts(tmp); tty_puts("%  ");
        /* simulate delay */
        for (volatile int j=0;j<200000;j++);
    }

    tty_cursor_show();
    return 0;
}
