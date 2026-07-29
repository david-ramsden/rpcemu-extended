/*
 * A track that the image does not contain must read as blank, not as the
 * track that happened to be in the buffer before.
 *
 * This matters beyond tidiness because adf_writeback() writes the whole track
 * buffer back to the image when the guest changes a single sector. If a short
 * read left the previous track's bytes in place, those bytes would be
 * committed to the image - silent corruption of the user's floppy.
 *
 * Short images are legitimate: adf_load() derives maxsector from the file
 * size, so seeking past the end is expected rather than an error. The fix is
 * therefore to zero-fill what was not read, not to refuse the seek.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disc.h"
#include "disc_adf.h"

/* disc_adf.c calls into the FDC and the disc layer. None of it is needed to
   drive a seek, so it is stubbed rather than linked. */
void fdc_data(uint8_t dat) { (void) dat; }
void fdc_finishread(void) {}
void fdc_notfound(void) {}
void fdc_datacrcerror(void) {}
void fdc_headercrcerror(void) {}
void fdc_writeprotect(void) {}
int  fdc_getdata(int last) { (void) last; return -1; }
void fdc_sectorid(uint8_t track, uint8_t side, uint8_t sector, uint8_t size,
                  uint8_t crc1, uint8_t crc2)
{
	(void) track; (void) side; (void) sector; (void) size;
	(void) crc1; (void) crc2;
}
void fdc_indexpulse(void) {}
int  disc_get_current_track(int drive) { (void) drive; return 0; }
void rpclog(const char *format, ...) { (void) format; }

/* Only the save/restore entry points need these, which this test does not
   exercise. */
void savestate_write_u8(FILE *f, uint8_t v) { (void) f; (void) v; }
void savestate_write_i32(FILE *f, int32_t v) { (void) f; (void) v; }
void savestate_write_rle(FILE *f, const void *data, size_t len)
{
	(void) f; (void) data; (void) len;
}
void savestate_read_rle(FILE *f, void *data, size_t len)
{
	(void) f; (void) data; (void) len;
}
uint8_t savestate_read_u8(FILE *f) { (void) f; return 0; }
int32_t savestate_read_i32(FILE *f) { (void) f; return 0; }

disc_funcs *drive_funcs[2];

static int failures;

static void check(int cond, const char *what)
{
	printf("  %-56s %s\n", what, cond ? "ok" : "FAIL");
	if (!cond) {
		failures++;
	}
}

/*
 * Write an image holding whole_tracks complete double-sided tracks followed by
 * a deliberately partial one, so the last seek runs off the end mid-track.
 */
static int write_image(const char *path, int sectors, int size,
                       int whole_tracks, int tail_bytes)
{
	const int track_bytes = sectors * size;
	FILE *f = fopen(path, "wb");
	int t, s, i;

	if (f == NULL) {
		return 0;
	}
	for (t = 0; t < whole_tracks; t++) {
		for (s = 0; s < 2; s++) {
			/* A distinct byte per track and side, so stale data is
			   recognisable as belonging to another track. */
			const int fill = 0xA0 + (t * 2) + s;

			for (i = 0; i < track_bytes; i++) {
				fputc(fill, f);
			}
		}
	}
	for (i = 0; i < tail_bytes; i++) {
		fputc(0xEE, f);
	}
	fclose(f);
	return 1;
}

int main(void)
{
	/* ADFS D/E geometry: 5 sectors of 1024 bytes, double sided. */
	const int sectors = 5, size = 1024;
	const int track_bytes = sectors * size;
	const int tail = 1000; /* a partial side 0 of track 2 */
	const char *path = "test_short.adf";
	const uint8_t *side0, *side1;
	int i, stale, blank;

	printf("adf short-read handling\n");

	if (!write_image(path, sectors, size, 2, tail)) {
		fprintf(stderr, "could not write the test image\n");
		return 1;
	}

	adf_init();
	adf_load(0, path, sectors, size, 1 /*dblside*/, 0 /*dblstep*/,
	         0 /*density*/, 0 /*skew*/);
	if (drive_funcs[0] == NULL) {
		fprintf(stderr, "adf_load refused the image\n");
		remove(path);
		return 1;
	}

	/* Track 1 is wholly present: the buffer should hold its own bytes. */
	drive_funcs[0]->seek(0, 1);
	side0 = adf_test_track_data(0, 0);
	side1 = adf_test_track_data(0, 1);
	check(side0[0] == 0xA2 && side0[track_bytes - 1] == 0xA2,
	      "a track that is present reads as itself (side 0)");
	check(side1[0] == 0xA3 && side1[track_bytes - 1] == 0xA3,
	      "a track that is present reads as itself (side 1)");

	/* Track 2 is only partly present. The bytes the image supplies must be
	   there, and everything past them must be blank rather than track 1. */
	drive_funcs[0]->seek(0, 2);
	side0 = adf_test_track_data(0, 0);
	side1 = adf_test_track_data(0, 1);

	check(side0[0] == 0xEE && side0[tail - 1] == 0xEE,
	      "the part of a short track the image holds is read");

	stale = 0;
	for (i = tail; i < track_bytes; i++) {
		if (side0[i] != 0) {
			stale = 1;
			break;
		}
	}
	check(!stale, "the rest of a short track is blank, not the last track");

	blank = 1;
	for (i = 0; i < track_bytes; i++) {
		if (side1[i] != 0) {
			blank = 0;
			break;
		}
	}
	check(blank, "a side that is absent entirely is blank");

	remove(path);
	printf("%s\n", failures ? "FAILED" : "passed");
	return failures ? 1 : 0;
}
