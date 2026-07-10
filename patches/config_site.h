/* Copy to pjproject/pjlib/include/pj/config_site.h before building.
 * Enables the AMR codecs JUICE requires; disables video. */
#define PJMEDIA_HAS_OPENCORE_AMRNB_CODEC   1
#define PJMEDIA_HAS_OPENCORE_AMRWB_CODEC   1
#define PJMEDIA_HAS_VIDEO                  0
