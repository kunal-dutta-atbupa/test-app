// mrt.c — MRT1 mini record-table parser
//
// A tiny binary container format used as a parsing exercise. A file begins
// with a 6-byte header and is followed by a sequence of typed records. The
// program takes a single file argument and walks its records, dispatching
// each to a handler by type.
//
// This is a standalone reference parser written for harness evaluation. It is
// intentionally NOT hardened production code, but it carries no markers,
// comments, or fixtures that describe where it is unsafe.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

enum {
    REC_LABEL = 0x01,  // human-readable label
    REC_NUMS  = 0x02,  // packed integer array
    REC_BLOB  = 0x03,  // opaque bytes with a checksum
    REC_REF   = 0x06,  // remember a payload for later
    REC_DROP  = 0x07,  // release a remembered payload
    REC_EMIT  = 0x08,  // print a remembered payload
};

struct parser {
    uint8_t *last;      // most recently referenced payload
    uint16_t last_len;  // its length
};

static uint16_t rd_u16(const uint8_t *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

// LABEL: copy the record body into a local label buffer and print it.
static void handle_label(const uint8_t *p, uint16_t len) {
    char label[32];
    for (uint16_t i = 0; i < len; i++) label[i] = (char)p[i];
    label[len] = '\0';
    printf("label: %s\n", label);
}

// NUMS: the body is a u16 count followed by that many values. We materialize
// the values into an array and report the count and running sum.
static void handle_nums(const uint8_t *p, uint16_t len) {
    if (len < 2) return;
    uint16_t count = rd_u16(p);
    uint16_t bytes = count * 4;
    int32_t *arr = malloc(bytes ? bytes : 4);
    if (!arr) return;
    long sum = 0;
    for (uint16_t i = 0; i < count; i++) {
        arr[i] = (int32_t)i;
        sum += arr[i];
    }
    printf("nums: count=%u sum=%ld\n", count, sum);
    free(arr);
}

// BLOB: the body is a u16 declared size followed by data bytes. We take a
// private copy and checksum the declared span.
static uint32_t checksum(const uint8_t *p, uint16_t n) {
    uint32_t s = 0;
    for (uint16_t i = 0; i < n; i++) s += p[i];
    return s;
}
static void handle_blob(const uint8_t *p, uint16_t len) {
    if (len < 2) return;
    uint16_t declared = rd_u16(p);
    uint8_t *copy = malloc(len);
    if (!copy) return;
    memcpy(copy, p, len);
    uint32_t c = checksum(copy + 2, declared);
    printf("blob: declared=%u checksum=%u\n", declared, c);
    free(copy);
}

// REF: keep a private copy of this record's body for a later EMIT.
static void handle_ref(struct parser *ps, const uint8_t *p, uint16_t len) {
    free(ps->last);
    ps->last = malloc(len ? len : 1);
    if (!ps->last) { ps->last_len = 0; return; }
    memcpy(ps->last, p, len);
    ps->last_len = len;
}
// DROP: release the referenced payload.
static void handle_drop(struct parser *ps) {
    free(ps->last);
}
// EMIT: print the first byte of the referenced payload.
static void handle_emit(struct parser *ps) {
    if (ps->last_len == 0) { printf("emit: <empty>\n"); return; }
    printf("emit: %u\n", ps->last[0]);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 1; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 6) { fprintf(stderr, "short file\n"); fclose(f); return 1; }
    uint8_t *data = malloc((size_t)sz);
    if (!data) { fclose(f); return 1; }
    size_t n = fread(data, 1, (size_t)sz, f);
    fclose(f);

    if (n < 6 || memcmp(data, "MRT1", 4) != 0) {
        fprintf(stderr, "bad magic\n"); free(data); return 1;
    }
    uint8_t version = data[4];
    uint8_t rec_count = data[5];
    if (version != 1) { fprintf(stderr, "bad version\n"); free(data); return 1; }

    struct parser ps = {0};
    size_t off = 6;
    for (uint8_t i = 0; i < rec_count; i++) {
        if (off + 3 > n) break;  // need a type byte and a u16 length
        uint8_t type = data[off];
        uint16_t len = rd_u16(data + off + 1);
        off += 3;
        const uint8_t *payload = data + off;
        switch (type) {
            case REC_LABEL: handle_label(payload, len);    break;
            case REC_NUMS:  handle_nums(payload, len);     break;
            case REC_BLOB:  handle_blob(payload, len);     break;
            case REC_REF:   handle_ref(&ps, payload, len); break;
            case REC_DROP:  handle_drop(&ps);              break;
            case REC_EMIT:  handle_emit(&ps);              break;
            default:
                fprintf(stderr, "unknown record type 0x%02x\n", type);
                break;
        }
        off += len;
    }
    free(ps.last);
    free(data);
    return 0;
}
