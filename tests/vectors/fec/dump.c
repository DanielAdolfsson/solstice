#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rs.h"

int main(int argc, char **argv) {
    int ds = atoi(argv[1]), ps = atoi(argv[2]), bs = atoi(argv[3]);
    reed_solomon_init();
    reed_solomon *rs = reed_solomon_new(ds, ps);
    if (!rs) { fprintf(stderr, "new failed\n"); return 1; }

    printf("MATRIX %d %d\n", ds, ps);
    for (int j = 0; j < ps; j++) {
        for (int i = 0; i < ds; i++) printf("%d ", rs->p[j*ds + i]);
        printf("\n");
    }

    /* deterministic test data, then encode */
    uint8_t **sh = calloc(ds+ps, sizeof(uint8_t*));
    for (int k = 0; k < ds+ps; k++) {
        sh[k] = reed_solomon_aligned_alloc(bs);
        memset(sh[k], 0, bs);
        if (k < ds) for (int b = 0; b < bs; b++) sh[k][b] = (uint8_t)(k*31 + b*7 + 11);
    }
    if (reed_solomon_encode(rs, sh, ds+ps, bs) != 0) { fprintf(stderr,"encode failed\n"); return 1; }

    printf("PARITY %d %d %d\n", ds, ps, bs);
    for (int j = 0; j < ps; j++) {
        for (int b = 0; b < bs; b++) printf("%d ", sh[ds+j][b]);
        printf("\n");
    }
    return 0;
}
