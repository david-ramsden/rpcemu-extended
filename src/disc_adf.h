extern void adf_init(void);

extern void adf_load(int drive, const char *fn, int sectors, int size, int dblside, int dblstep, int density, int skew);

#ifdef RPCEMU_DISC_TEST
/* Read access to a drive's track buffer, so a test can see what a seek left
   there. Built only for tests/test_disc_short_read. */
extern const uint8_t *adf_test_track_data(int drive, int side);
#endif
