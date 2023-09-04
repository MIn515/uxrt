/*
 * XIP ROM file system
 *
 * This is a minimal in-memory filesystem for use in the UX/RT boot image. It is
 * based on a modified Multiboot2 header with different tags, so it can be 
 * parsed with only a Multiboot2 parser rather than requiring extra code.
 *
 */

/* TODO: everything (support the new pure MBH version; this can probably be done by linking with multiboot2_lib) 
 *
 * The new implementation should just function more like an archiver and iterate over all files in the image */
