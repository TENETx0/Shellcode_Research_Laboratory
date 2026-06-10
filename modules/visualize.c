#define _GNU_SOURCE
#include "common.h"
#include "modules.h"

#include <math.h>
#include <ncurses.h>
#include <stdlib.h>
#include <string.h>

void help_visualize(void)
{
    printf(
"Purpose:  Interactive terminal visualisation of a file.\n"
"Syntax:   srl visualize <file>\n"
"Views (keys): [1] hex  [2] byte-frequency  [3] sliding entropy   q quit\n"
"Requires an interactive TTY (uses ncurses). Falls back to a static ASCII\n"
"summary when stdout is not a terminal.\n"
"Example:  srl visualize payload.bin\n");
}

/* sliding-window entropy across the file, drawn as a column graph */
static void draw_entropy(const unsigned char *b, size_t n, int rows, int cols)
{
    if (cols < 2 || n == 0) return;
    size_t win = n / (size_t)cols; if (win < 1) win = 1;
    for (int c = 0; c < cols; c++) {
        size_t off = (size_t)c * win;
        size_t w = (off + win <= n) ? win : (n - off);
        if (w == 0) break;
        double h = srl_shannon_entropy(b + off, w);
        int barh = (int)((h / 8.0) * (rows - 3));
        for (int r = 0; r < barh; r++)
            mvaddch(rows - 3 - r, c, ACS_CKBOARD);
    }
}

static void draw_freq(const unsigned char *b, size_t n, int rows, int cols)
{
    size_t freq[256]; srl_byte_freq(b, n, freq);
    size_t maxf = 1; for (int i = 0; i < 256; i++) if (freq[i] > maxf) maxf = freq[i];
    int width = cols < 256 ? cols : 256;
    for (int i = 0; i < width; i++) {
        int barh = (int)((freq[i] * (size_t)(rows - 3)) / maxf);
        for (int r = 0; r < barh; r++) mvaddch(rows - 3 - r, i, ACS_VLINE);
    }
}

static void draw_hex(const unsigned char *b, size_t n, int rows, int top)
{
    int line = 0;
    for (size_t off = (size_t)top * 16; off < n && line < rows - 3; off += 16, line++) {
        char buf[128]; int p = 0;
        p += snprintf(buf + p, sizeof(buf) - (size_t)p, "%08zx  ", off);
        for (int i = 0; i < 16; i++) {
            if (off + (size_t)i < n) p += snprintf(buf+p, sizeof(buf)-(size_t)p, "%02x ", b[off+i]);
            else                     p += snprintf(buf+p, sizeof(buf)-(size_t)p, "   ");
        }
        p += snprintf(buf+p, sizeof(buf)-(size_t)p, " |");
        for (int i = 0; i < 16 && off+(size_t)i < n; i++) {
            unsigned char c = b[off+i];
            buf[p++] = (char)((c >= 0x20 && c < 0x7f) ? c : '.');
        }
        buf[p++] = '|'; buf[p] = '\0';
        mvaddnstr(line, 0, buf, COLS - 1);
    }
}

int cmd_visualize(int argc, char **argv)
{
    if (srl_wants_help(argc, argv) || argc < 1) { help_visualize(); return argc < 1; }

    const char *file = argv[0];
    size_t n = 0;
    unsigned char *b = srl_read_file(file, &n);
    if (!b) { fprintf(stderr, "error: cannot read %s\n", file); return 1; }

    if (!srl_is_tty(stdout)) {           /* non-interactive fallback */
        printf("entropy=%.4f size=%zu (run on a TTY for interactive view)\n",
               srl_shannon_entropy(b, n), n);
        free(b); return 0;
    }

    initscr(); cbreak(); noecho(); keypad(stdscr, TRUE); curs_set(0);
    int view = 1, top = 0, ch = 0;
    do {
        erase();
        int rows = LINES, cols = COLS;
        if      (view == 1) draw_hex(b, n, rows, top);
        else if (view == 2) draw_freq(b, n, rows, cols);
        else                draw_entropy(b, n, rows, cols);

        mvprintw(LINES - 2, 0, "%s | %zu bytes | view %d", srl_basename(file), n, view);
        mvprintw(LINES - 1, 0, "[1]hex [2]freq [3]entropy  arrows scroll  q quit");
        refresh();

        ch = getch();
        if      (ch == '1') { view = 1; top = 0; }
        else if (ch == '2')   view = 2;
        else if (ch == '3')   view = 3;
        else if (ch == KEY_DOWN && view == 1) top++;
        else if (ch == KEY_UP   && view == 1 && top > 0) top--;
    } while (ch != 'q' && ch != 'Q');

    endwin();
    free(b);
    return 0;
}
