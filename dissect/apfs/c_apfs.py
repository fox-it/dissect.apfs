# Resources:
# - https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
# - https://github.com/sgan81/apfs-fuse
# - https://github.com/linux-apfs/linux-apfs-rw
from dissect.cstruct import cstruct

apfs_def = """
/*
 * Common types
 */

typedef uint16_t mode_t;
typedef uint32_t uid_t;
typedef uint32_t gid_t;

typedef uint32_t cp_key_class_t;
typedef uint32_t cp_key_os_version_t;
typedef uint16_t cp_key_revision_t;
typedef uint32_t crypto_flags_t;

typedef int64_t paddr_t;

struct prange {
    paddr_t     pr_start_paddr;
    uint64_t    pr_block_count;
};
typedef struct prange prange_t;

typedef uint64_t oid_t;
typedef uint64_t xid_t;

/*
 * Objects
 */

/* Object Identifier Constants */
#define OID_NX_SUPERBLOCK               1
#define OID_INVALID                     0
#define OID_RESERVED_COUNT              1024

/* Object Type Masks */
#define OBJECT_TYPE_MASK                0x0000ffff
#define OBJECT_TYPE_FLAGS_MASK          0xffff0000
#define OBJ_STORAGETYPE_MASK            0xc0000000
#define OBJECT_TYPE_FLAGS_DEFINED_MASK  0xf8000000

/* Object Types */
#define OBJECT_TYPE_NX_SUPERBLOCK       0x00000001
#define OBJECT_TYPE_BTREE               0x00000002
#define OBJECT_TYPE_BTREE_NODE          0x00000003
#define OBJECT_TYPE_SPACEMAN            0x00000005
#define OBJECT_TYPE_SPACEMAN_CAB        0x00000006
#define OBJECT_TYPE_SPACEMAN_CIB        0x00000007
#define OBJECT_TYPE_SPACEMAN_BITMAP     0x00000008
#define OBJECT_TYPE_SPACEMAN_FREE_QUEUE 0x00000009
#define OBJECT_TYPE_EXTENT_LIST_TREE    0x0000000a
#define OBJECT_TYPE_OMAP                0x0000000b
#define OBJECT_TYPE_CHECKPOINT_MAP      0x0000000c
#define OBJECT_TYPE_FS                  0x0000000d
#define OBJECT_TYPE_FSTREE              0x0000000e
#define OBJECT_TYPE_BLOCKREFTREE        0x0000000f
#define OBJECT_TYPE_SNAPMETATREE        0x00000010
#define OBJECT_TYPE_NX_REAPER           0x00000011
#define OBJECT_TYPE_NX_REAP_LIST        0x00000012
#define OBJECT_TYPE_OMAP_SNAPSHOT       0x00000013
#define OBJECT_TYPE_EFI_JUMPSTART       0x00000014
#define OBJECT_TYPE_FUSION_MIDDLE_TREE  0x00000015
#define OBJECT_TYPE_NX_FUSION_WBC       0x00000016
#define OBJECT_TYPE_NX_FUSION_WBC_LIST  0x00000017
#define OBJECT_TYPE_ER_STATE            0x00000018
#define OBJECT_TYPE_GBITMAP             0x00000019
#define OBJECT_TYPE_GBITMAP_TREE        0x0000001a
#define OBJECT_TYPE_GBITMAP_BLOCK       0x0000001b
#define OBJECT_TYPE_ER_RECOVERY_BLOCK   0x0000001c
#define OBJECT_TYPE_SNAP_META_EXT       0x0000001d
#define OBJECT_TYPE_INTEGRITY_META      0x0000001e
#define OBJECT_TYPE_FEXT_TREE           0x0000001f
#define OBJECT_TYPE_RESERVED_20         0x00000020
#define OBJECT_TYPE_INVALID             0x00000000
#define OBJECT_TYPE_TEST                0x000000ff
#define OBJECT_TYPE_CONTAINER_KEYBAG    0x6b657973      // 'keys'
#define OBJECT_TYPE_VOLUME_KEYBAG       0x72656373      // 'recs'
#define OBJECT_TYPE_MEDIA_KEYBAG        0x6d6b6579      // 'mkey'

// As a cstruct enum
enum OBJECT_TYPE {
    NX_SUPERBLOCK                       = 0x00000001,
    BTREE                               = 0x00000002,
    BTREE_NODE                          = 0x00000003,
    SPACEMAN                            = 0x00000005,
    SPACEMAN_CAB                        = 0x00000006,
    SPACEMAN_CIB                        = 0x00000007,
    SPACEMAN_BITMAP                     = 0x00000008,
    SPACEMAN_FREE_QUEUE                 = 0x00000009,
    EXTENT_LIST_TREE                    = 0x0000000a,
    OMAP                                = 0x0000000b,
    CHECKPOINT_MAP                      = 0x0000000c,
    FS                                  = 0x0000000d,
    FSTREE                              = 0x0000000e,
    BLOCKREFTREE                        = 0x0000000f,
    SNAPMETATREE                        = 0x00000010,
    NX_REAPER                           = 0x00000011,
    NX_REAP_LIST                        = 0x00000012,
    OMAP_SNAPSHOT                       = 0x00000013,
    EFI_JUMPSTART                       = 0x00000014,
    FUSION_MIDDLE_TREE                  = 0x00000015,
    NX_FUSION_WBC                       = 0x00000016,
    NX_FUSION_WBC_LIST                  = 0x00000017,
    ER_STATE                            = 0x00000018,
    GBITMAP                             = 0x00000019,
    GBITMAP_TREE                        = 0x0000001a,
    GBITMAP_BLOCK                       = 0x0000001b,
    ER_RECOVERY_BLOCK                   = 0x0000001c,
    SNAP_META_EXT                       = 0x0000001d,
    INTEGRITY_META                      = 0x0000001e,
    FEXT_TREE                           = 0x0000001f,
    RESERVED_20                         = 0x00000020,
    INVALID                             = 0x00000000,
    TEST                                = 0x000000ff,
    CONTAINER_KEYBAG                    = 0x6b657973,   // 'keys'
    VOLUME_KEYBAG                       = 0x72656373,   // 'recs'
    MEDIA_KEYBAG                        = 0x6d6b6579,   // 'mkey'
};

/* Object type flags */
#define OBJ_VIRTUAL                     0x00000000
#define OBJ_EPHEMERAL                   0x80000000
#define OBJ_PHYSICAL                    0x40000000
#define OBJ_NOHEADER                    0x20000000
#define OBJ_ENCRYPTED                   0x10000000
#define OBJ_NONPERSISTENT               0x08000000

// As a cstruct enum
enum OBJ {
    VIRTUAL                             = 0x00000000,
    EPHEMERAL                           = 0x80000000,
    PHYSICAL                            = 0x40000000,
    NOHEADER                            = 0x20000000,
    ENCRYPTED                           = 0x10000000,
    NONPERSISTENT                       = 0x08000000,
};

#define MAX_CKSUM_SIZE                  8

struct obj_phys {
    char        o_cksum[MAX_CKSUM_SIZE];
    oid_t       o_oid;
    xid_t       o_xid;
    uint32_t    o_type;
    uint32_t    o_subtype;
};
typedef struct obj_phys obj_phys_t;

/*
 * Object Map
 */

/* Object Map Value Flags */
#define OMAP_VAL_DELETED                0x00000001
#define OMAP_VAL_SAVED                  0x00000002
#define OMAP_VAL_ENCRYPTED              0x00000004
#define OMAP_VAL_NOHEADER               0x00000008
#define OMAP_VAL_CRYPTO_GENERATION      0x00000010

/* Snapshot Flags */
#define OMAP_SNAPSHOT_DELETED           0x00000001
#define OMAP_SNAPSHOT_REVERTED          0x00000002

/* Object Map Flags */
#define OMAP_MANUALLY_MANAGED           0x00000001
#define OMAP_ENCRYPTING                 0x00000002
#define OMAP_DECRYPTING                 0x00000004
#define OMAP_KEYROLLING                 0x00000008
#define OMAP_CRYPTO_GENERATION          0x00000010

#define OMAP_VALID_FLAGS                0x0000001f

/* Object Map Constants */
#define OMAP_MAX_SNAP_COUNT             0xffffffff

/* Object Map Reaper Phases */
#define OMAP_REAP_PHASE_MAP_TREE        1
#define OMAP_REAP_PHASE_SNAPSHOT_TREE   2

struct omap_phys {
    obj_phys_t  om_o;
    uint32_t    om_flags;
    uint32_t    om_snap_count;
    uint32_t    om_tree_type;
    uint32_t    om_snapshot_tree_type;
    oid_t       om_tree_oid;
    oid_t       om_snapshot_tree_oid;
    xid_t       om_most_recent_snap;
    xid_t       om_pending_revert_min;
    xid_t       om_pending_revert_max;
};
typedef struct omap_phys omap_phys_t;

struct omap_key {
    oid_t       ok_oid;
    xid_t       ok_xid;
};
typedef struct omap_key omap_key_t;

struct omap_val {
    uint32_t    ov_flags;
    uint32_t    ov_size;
    paddr_t     ov_paddr;
};
typedef struct omap_val omap_val_t;

struct omap_snapshot {
    uint32_t    oms_flags;
    uint32_t    oms_pad;
    oid_t       oms_oid;
};
typedef struct omap_snapshot omap_snapshot_t;

/*
 * B-Trees
 */

/* B-Tree flags */
#define BTREE_UINT64_KEYS               0x00000001
#define BTREE_SEQUENTIAL_INSERT         0x00000002
#define BTREE_ALLOW_GHOSTS              0x00000004
#define BTREE_EPHEMERAL                 0x00000008
#define BTREE_PHYSICAL                  0x00000010
#define BTREE_NONPERSISTENT             0x00000020
#define BTREE_KV_NONALIGNED             0x00000040
#define BTREE_HASHED                    0x00000080
#define BTREE_NOHEADER                  0x00000100

// As a cstruct flag
flag BTREE {
    UINT64_KEYS                         = 0x00000001,
    SEQUENTIAL_INSERT                   = 0x00000002,
    ALLOW_GHOSTS                        = 0x00000004,
    EPHEMERAL                           = 0x00000008,
    PHYSICAL                            = 0x00000010,
    NONPERSISTENT                       = 0x00000020,
    KV_NONALIGNED                       = 0x00000040,
    HASHED                              = 0x00000080,
    NOHEADER                            = 0x00000100,
};

/* B-Tree Table of Contents Constants */
#define BTREE_TOC_ENTRY_INCREMENT       8
#define BTREE_TOC_ENTRY_MAX_UNUSED      (2 * BTREE_TOC_ENTRY_INCREMENT)

/* B-Tree Node Flags */
#define BTNODE_ROOT                     0x0001
#define BTNODE_LEAF                     0x0002

#define BTNODE_FIXED_KV_SIZE            0x0004
#define BTNODE_HASHED                   0x0008
#define BTNODE_NOHEADER                 0x0010

#define BTNODE_CHECK_KOFF_INVAL         0x8000

// As a cstruct flag
flag BTNODE {
    ROOT                                = 0x0001,
    LEAF                                = 0x0002,
    FIXED_KV_SIZE                       = 0x0004,
    HASHED                              = 0x0008,
    NOHEADER                            = 0x0010,
    CHECK_KOFF_INVAL                    = 0x8000,
};

/* B-Tree Node Constants */
#define BTREE_NODE_SIZE_DEFAULT         4096
#define BTREE_NODE_MIN_ENTRY_COUNT      4

struct nloc {
    uint16_t    off;
    uint16_t    len;
};
typedef struct nloc nloc_t;

struct btree_node_phys {
    obj_phys_t  btn_o;
    uint16_t    btn_flags;
    uint16_t    btn_level;
    uint32_t    btn_nkeys;
    nloc_t      btn_table_space;
    nloc_t      btn_free_space;
    nloc_t      btn_key_free_list;
    nloc_t      btn_val_free_list;
    // uint64_t    btn_data[];
};
typedef struct btree_node_phys btree_node_phys_t;

struct btree_info_fixed {
    uint32_t    bt_flags;
    uint32_t    bt_node_size;
    uint32_t    bt_key_size;
    uint32_t    bt_val_size;
};
typedef struct btree_info_fixed btree_info_fixed_t;

struct btree_info {
    btree_info_fixed_t  bt_fixed;
    uint32_t            bt_longest_key;
    uint32_t            bt_longest_val;
    uint64_t            bt_key_count;
    uint64_t            bt_node_count;
};
typedef struct btree_info btree_info_t;

#define BTREE_NODE_HASH_SIZE_MAX        64

struct btn_index_node_val {
    oid_t       binv_child_oid;
    char        binv_child_hash[BTREE_NODE_HASH_SIZE_MAX];
};
typedef struct btn_index_node_val btn_index_node_val_t;

#define BTOFF_INVALID                   0xffff

struct kvloc {
    nloc_t      k;
    nloc_t      v;
};
typedef struct kvloc kvloc_t;

struct kvoff {
    uint16_t    k;
    uint16_t    v;
};
typedef struct kvoff kvoff_t;

/*
 * File-System Objects
 */

struct j_key {
    uint64_t    obj_id_and_type;
};
typedef struct j_key j_key_t;

#define OBJ_ID_MASK                     0x0fffffffffffffff
#define OBJ_TYPE_MASK                   0xf000000000000000
#define OBJ_TYPE_SHIFT                  60

#define SYSTEM_OBJ_ID_MARK              0x0fffffff00000000

struct j_inode_key {
    j_key_t     hdr;
};
typedef struct j_inode_key j_inode_key_t;

struct j_inode_val {
    uint64_t    parent_id;
    uint64_t    private_id;

    uint64_t    create_time;
    uint64_t    mod_time;
    uint64_t    change_time;
    uint64_t    access_time;

    uint64_t    internal_flags;

    union {
        int32_t nchildren;
        int32_t nlink;
    };

    cp_key_class_t  default_protection_class;
    uint32_t    write_generation_counter;
    uint32_t    bsd_flags;
    uid_t       owner;
    gid_t       group;
    mode_t      mode;
    uint16_t    pad1;
    uint64_t    uncompressed_size;
    // uint8_t     xfields[];
};
typedef struct j_inode_val j_inode_val_t;

struct j_drec_key {
    j_key_t     hdr;
    uint16_t    name_len;
    char        name[name_len];
};
typedef struct j_drec_key j_drec_key_t;

#define J_DREC_LEN_MASK                 0x000003ff
#define J_DREC_HASH_MASK                0xfffffc00
#define J_DREC_HASH_SHIFT               10

struct j_drec_hashed_key {
    j_key_t     hdr;
    uint32_t    name_len_and_hash;
    char        name[name_len_and_hash & J_DREC_LEN_MASK];
};
typedef struct j_drec_hashed_key j_drec_hashed_key_t;

struct j_drec_val {
    uint64_t    file_id;
    uint64_t    date_added;
    uint16_t    flags;
    // uint8_t xfields[];
};
typedef struct j_drec_val j_drec_val_t;

struct j_dir_stats_key {
    j_key_t     hdr;
};
typedef struct j_dir_stats_key j_dir_stats_key_t;

struct j_dir_stats_val {
    uint64_t    num_children;
    uint64_t    total_size;
    uint64_t    chained_key;
    uint64_t    gen_count;
};
typedef struct j_dir_stats_val j_dir_stats_val_t;

struct j_xattr_key {
    j_key_t     hdr;
    uint16_t    name_len;
    char        name[name_len];
};
typedef struct j_xattr_key j_xattr_key_t;

struct j_xattr_val {
    uint16_t    flags;
    uint16_t    xdata_len;
    char        xdata[xdata_len];
};
typedef struct j_xattr_val j_xattr_val_t;

/* File-System Contants */
enum APFS_TYPE {
    ANY                                 = 0,
    SNAP_METADATA                       = 1,
    EXTENT                              = 2,
    INODE                               = 3,
    XATTR                               = 4,
    SIBLING_LINK                        = 5,
    DSTREAM_ID                          = 6,
    CRYPTO_STATE                        = 7,
    FILE_EXTENT                         = 8,
    DIR_REC                             = 9,
    DIR_STATS                           = 10,
    SNAP_NAME                           = 11,
    SIBLING_MAP                         = 12,
    FILE_INFO                           = 13,
    MAX_VALID                           = 13,
    MAX                                 = 15,
    INVALID                             = 15,
};
/* typedef enum j_obj_types; */

enum APFS_KIND {
    ANY                                 = 0,
    NEW                                 = 1,
    UPDATE                              = 2,
    DEAD                                = 3,
    UPDATE_REFCNT                       = 4,
    INVALID                             = 255
};
/* typedef enum j_obj_kinds; */

flag INODE {
    IS_APFS_PRIVATE                     = 0x00000001,
    MAINTAIN_DIR_STATS                  = 0x00000002,
    DIR_STATS_ORIGIN                    = 0x00000004,
    PROT_CLASS_EXPLICIT                 = 0x00000008,
    WAS_CLONED                          = 0x00000010,
    FLAG_UNUSED                         = 0x00000020,
    HAS_SECURITY_EA                     = 0x00000040,
    BEING_TRUNCATED                     = 0x00000080,
    HAS_FINDER_INFO                     = 0x00000100,
    IS_SPARSE                           = 0x00000200,
    WAS_EVER_CLONED                     = 0x00000400,
    ACTIVE_FILE_TRIMMED                 = 0x00000800,
    PINNED_TO_MAIN                      = 0x00001000,
    PINNED_TO_TIER2                     = 0x00002000,
    HAS_RSRC_FORK                       = 0x00004000,
    NO_RSRC_FORK                        = 0x00008000,
    ALLOCATION_SPILLEDOVER              = 0x00010000,
    FAST_PROMOTE                        = 0x00020000,
    HAS_UNCOMPRESSED_SIZE               = 0x00040000,
    IS_PURGEABLE                        = 0x00080000,
    WANTS_TO_BE_PURGEABLE               = 0x00100000,
    IS_SYNC_ROOT                        = 0x00200000,
    SNAPSHOT_COW_EXEMPTION              = 0x00400000,
    INHERITED_INTERNAL_FLAGS            = 0x00400002,
    CLONED_INTERNAL_FLAGS               = 0x0000c000,
};
/* typedef enum j_inode_flags */

#define APFS_INODE_PINNED_MASK          INODE.PINNED_TO_MAIN | INODE.PINNED_TO_TIER2

/* Super-user and owner changeable flags. */
#define UF_NODUMP                       0x00000001      /* do not dump file */
#define UF_IMMUTABLE                    0x00000002      /* file may not be changed */
#define UF_APPEND                       0x00000004      /* writes to file may only append */
#define UF_OPAQUE                       0x00000008      /* directory is opaque wrt. union */
#define UF_NOUNLINK                     0x00000010      /* file may not be removed or renamed */
#define UF_COMPRESSED                   0x00000020      /* file is compressed (some file-systems) */
#define UF_TRACKED                      0x00000040
#define UF_DATAVAULT                    0x00000080      /* entitlement required for reading and writing */
#define UF_HIDDEN                       0x00008000      /* hint that this item should not be displayed in a GUI */

/* Super-user changeable flags. */
#define SF_SUPPORTED                    0x009f0000      /* mask of superuser supported flags */
#define SF_SETTABLE                     0x3fff0000      /* mask of superuser changeable flags */
#define SF_SYNTHETIC                    0xc0000000      /* mask of system read-only synthetic flags */
#define SF_ARCHIVED                     0x00010000      /* file is archived */
#define SF_IMMUTABLE                    0x00020000      /* file may not be changed */
#define SF_APPEND                       0x00040000      /* writes to file may only append */
#define SF_RESTRICTED                   0x00080000      /* entitlement required for writing */
#define SF_NOUNLINK                     0x00100000      /* Item may not be removed, renamed or mounted on */
#define SF_SNAPSHOT                     0x00200000      /* snapshot inode */
#define SF_FIRMLINK                     0x00800000      /* file is a firmlink */
#define SF_DATALESS                     0x40000000      /* file is dataless object */

flag XATTR {
    DATA_STREAM                         = 0x00000001,
    DATA_EMBEDDED                       = 0x00000002,
    FILE_SYSTEM_OWNED                   = 0x00000004,
    RESERVED_8                          = 0x00000008,
    RESERVED_10                         = 0x00000010,
};
/* typedef enum j_xattr_flags; */

#define DREC_TYPE_MASK                  0x000f
// typedef enum {
//     DREC_TYPE_MASK                      = 0x000f,
//     RESERVED_10                         = 0x0010
// } dir_rec_flags;

/* Inode Numbers */
#define INVALID_INO_NUM                 0

#define ROOT_DIR_PARENT                 1
#define ROOT_DIR_INO_NUM                2
#define PRIV_DIR_INO_NUM                3
#define SNAP_DIR_INO_NUM                6
#define PURGEABLE_DIR_INO_NUM           7

#define MIN_USER_INO_NUM                16

#define UNIFIED_ID_SPACE_MARK           0x0800000000000000

/* Extended Attributes Constants */
#define XATTR_MAX_EMBEDDED_SIZE         3804
#define SYMLINK_EA_NAME                 "com.apple.fs.symlink"
#define FIRMLINK_EA_NAME                "com.apple.fs.firmlink"
#define APFS_COW_EXEMPT_COUNT_NAME      "com.apple.fs.cow-exempt-file-count"

/* File-System Object Constants */
#define OWNING_OBJ_ID_INVALID           ~0ULL
#define OWNING_OBJ_ID_UNKNOWN           ~1ULL

#define JOBJ_MAX_KEY_SIZE               832
#define JOBJ_MAX_VALUE_SIZE             3808

#define MIN_DOC_ID                      3

/* File Extent Constants */
#define FEXT_CRYPTO_ID_IS_TWEAK         0x01

/* Directory Entry File Types */
enum DT {
    UNKNOWN                             = 0,
    FIFO                                = 1,
    CHR                                 = 2,
    DIR                                 = 4,
    BLK                                 = 6,
    REG                                 = 8,
    LNK                                 = 10,
    SOCK                                = 12,
    WHT                                 = 14,
};

/*
 * Compression
 */

struct decmpfs_header {
    uint32_t    magic;
    uint32_t    algorithm;
    uint64_t    uncompressed_size;
};

#define DECMPFS_MAGIC                   b"cmpf"
#define DECMPFS_BLOCK_SIZE              0x10000

#define DECMPFS_ZLIB_ATTR               3
#define DECMPFS_ZLIB_RSRC               4
#define DECMPFS_LZVN_ATTR               7
#define DECMPFS_LZVN_RSRC               8
#define DECMPFS_PLAIN_ATTR              9
#define DECMPFS_PLAIN_RSRC              10
#define DECMPFS_LZFSE_ATTR              11
#define DECMPFS_LZFSE_RSRC              12
#define DECMPFS_LZBITMAP_ATTR           13
#define DECMPFS_LZBITMAP_RSRC           14

/*
 * Data Streams
 */

struct j_phys_ext_key {
    j_key_t     hdr;
};
typedef struct j_phys_ext_key j_phys_ext_key_t;

struct j_phys_ext_val {
    uint64_t    len_and_kind;
    uint64_t    owning_obj_id;
    int32_t     refcnt;
};
typedef struct j_phys_ext_val j_phys_ext_val_t;

#define PEXT_LEN_MASK                   0x0fffffffffffffff
#define PEXT_KIND_MASK                  0xf000000000000000
#define PEXT_KIND_SHIFT                 60

struct j_file_extent_key {
    j_key_t     hdr;
    uint64_t    logical_addr;
};
typedef struct j_file_extent_key j_file_extent_key_t;

struct j_file_extent_val {
    uint64_t    len_and_flags;
    uint64_t    phys_block_num;
    uint64_t    crypto_id;
};
typedef struct j_file_extent_val j_file_extent_val_t;

#define J_FILE_EXTENT_LEN_MASK          0x00ffffffffffffff
#define J_FILE_EXTENT_FLAG_MASK         0xff00000000000000
#define J_FILE_EXTENT_FLAG_SHIFT        56

struct j_dstream_id_key {
    j_key_t     hdr;
};
typedef struct j_dstream_id_key j_dstream_id_key_t;

struct j_dstream_id_val {
    uint32_t    refcnt;
};
typedef struct j_dstream_id_val j_dstream_id_val_t;

struct j_dstream {
    uint64_t    size;
    uint64_t    alloced_size;
    uint64_t    default_crypto_id;
    uint64_t    total_bytes_written;
    uint64_t    total_bytes_read;
};
typedef struct j_dstream j_dstream_t;

struct j_xattr_dstream {
    uint64_t    xattr_obj_id;
    j_dstream_t dstream;
};
typedef struct j_xattr_dstream j_xattr_dstream_t;

/*
 * Extended fields
 */

struct x_field {
    uint8_t     x_type;
    uint8_t     x_flags;
    uint16_t    x_size;
};
typedef struct x_field x_field_t;

struct xf_blob {
    uint16_t    xf_num_exts;
    uint16_t    xf_used_data;
    x_field_t   xf_exts[xf_num_exts];
    char        xf_data[xf_used_data];
};
typedef struct xf_blob xf_blob_t;

/* Extended Field Types */
enum DREC_EXT_TYPE {
    SIBLING_ID                          = 1,
};

enum INO_EXT_TYPE {
    SNAP_XID                            = 1,
    DELTA_TREE_OID                      = 2,
    DOCUMENT_ID                         = 3,
    NAME                                = 4,
    PREV_FSIZE                          = 5,
    RESERVED_6                          = 6,
    FINDER_INFO                         = 7,
    DSTREAM                             = 8,
    RESERVED_9                          = 9,
    DIR_STATS_KEY                       = 10,
    FS_UUID                             = 11,
    RESERVED_12                         = 12,
    SPARSE_BYTES                        = 13,
    RDEV                                = 14,
    PURGEABLE_FLAGS                     = 15,
    ORIG_SYNC_ROOT_ID                   = 16,
};

/* Extended Field Flags */
flag XF {
    DATA_DEPENDENT                      = 0x0001,
    DO_NOT_COPY                         = 0x0002,
    RESERVED_4                          = 0x0004,
    CHILDREN_INHERIT                    = 0x0008,
    USER_FIELD                          = 0x0010,
    SYSTEM_FIELD                        = 0x0020,
    RESERVED_40                         = 0x0040,
    RESERVED_80                         = 0x0080,
};

/*
 * Siblings
 */

struct j_sibling_key {
    j_key_t     hdr;
    uint64_t    sibling_id;
};
typedef struct j_sibling_key j_sibling_key_t;

struct j_sibling_val {
    uint64_t    parent_id;
    uint16_t    name_len;
    char        name[name_len];
};
typedef struct j_sibling_val j_sibling_val_t;

struct j_sibling_map_key {
    j_key_t     hdr;
};
typedef struct j_sibling_map_key j_sibling_map_key_t;

struct j_sibling_map_val {
    uint64_t    file_id;
};
typedef struct j_sibling_map_val j_sibling_map_val_t;

/*
 * Snapshot Metadata
 */

struct j_snap_metadata_key {
    j_key_t     hdr;
};
typedef struct j_snap_metadata_key j_snap_metadata_key_t;

struct j_snap_metadata_val {
    oid_t       extentref_tree_oid;
    oid_t       sblock_oid;
    uint64_t    create_time;
    uint64_t    change_time;
    uint64_t    inum;
    uint32_t    extentref_tree_type;
    uint32_t    flags;
    uint16_t    name_len;
    char        name[name_len];
};
typedef struct j_snap_metadata_val j_snap_metadata_val_t;

struct j_snap_name_key {
    j_key_t     hdr;
    uint16_t    name_len;
    char        name[name_len];
};
typedef struct j_snap_name_key j_snap_name_key_t;

struct j_snap_name_val {
    xid_t       snap_xid;
};
typedef struct j_snap_name_val j_snap_name_val_t;

enum SNAP_META {
    PENDING_DATALESS                    = 0x00000001,
    MERGE_IN_PROGRESS                   = 0x00000002,
};
/* typedef enum snap_meta_flags; */

typedef struct snap_meta_ext {
    uint32_t    sme_version;
    uint32_t    sme_flags;
    xid_t       sme_snap_xid;
    char        sme_uuid[16];
    uint64_t    sme_token;
};
typedef struct snap_meta_ext snap_meta_ext_t;

struct snap_meta_ext_obj_phys {
    obj_phys_t      smeop_o;
    snap_meta_ext_t smeop_sme;
};
typedef struct snap_meta_ext_obj_phys snap_meta_ext_obj_phys_t;

/*
 * Encryption
 */

#define CRYPTO_SW_ID                    4
#define CRYPTO_RESERVED_5               5
#define APFS_UNASSIGNED_CRYPTO_ID       (~0)

struct keybag_entry {
    char        ke_uuid[16];
    uint16_t    ke_tag;
    uint16_t    ke_keylen;
    uint8_t     padding[4];
    char        ke_keydata[0];
};
typedef struct keybag_entry keybag_entry_t;

#define APFS_VOL_KEYBAG_ENTRY_MAX_SIZE  512
#define APFS_FV_PERSONAL_RECOVERY_KEY_UUID  "EBC6C064-0000-11AA-AA11-00306543ECAC"

struct kb_locker {
    uint16_t        kl_version;
    uint16_t        kl_nkeys;
    uint32_t        kl_nbytes;
    uint8_t         padding[8];
    keybag_entry_t  kl_entries[0];
};
typedef struct kb_locker kb_locker_t;

#define APFS_KEYBAG_VERSION             2

struct media_keybag {
    obj_phys_t  mk_obj;
    kb_locker_t mk_locker;
};
typedef struct media_keybag media_keybag_t;

enum KB_TAG {
    UNKNOWN                             = 0,
    RESERVED_1                          = 1,
    VOLUME_KEY                          = 2,
    VOLUME_UNLOCK_RECORDS               = 3,
    VOLUME_PASSPHRASE_HINT              = 4,
    WRAPPING_M_KEY                      = 5,
    KB_TAG_VOLUME_M_KEY                 = 6,
    KB_TAG_RESERVED_F8                  = 0xF8,
};

enum PROTECTION_CLASS {
    DIR_NONE                            = 0,
    A                                   = 1,
    B                                   = 2,
    C                                   = 3,
    D                                   = 4,
    F                                   = 6,
    M                                   = 14,
};

#define CP_EFFECTIVE_CLASSMASK          0x0000001f

struct wrapped_meta_crypto_state {
    uint16_t            major_version;
    uint16_t            minor_version;
    crypto_flags_t      cpflags;
    cp_key_class_t      persistent_class;
    cp_key_os_version_t key_os_version;
    cp_key_revision_t   key_revision;
    uint16_t            unused;
};
typedef struct wrapped_meta_crypto_state wrapped_meta_crypto_state_t;

struct wrapped_crypto_state {
    uint16_t            major_version;
    uint16_t            minor_version;
    crypto_flags_t      cpflags;
    cp_key_class_t      persistent_class;
    cp_key_os_version_t key_os_version;
    cp_key_revision_t   key_revision;
    uint16_t            key_len;
    char                persistent_key[key_len];
};
typedef struct wrapped_crypto_state wrapped_crypto_state_t;

struct j_crypto_key {
    j_key_t     hdr;
};
typedef struct j_crypto_key j_crypto_key_t;

struct j_crypto_val {
    uint32_t    refcnt;
    wrapped_crypto_state_t  state;
};
typedef struct j_crypto_val j_crypto_val_t;

/*
 * Encryption Rolling
 */

enum ER_PHASE {
    OMAP_ROLL                           = 1,
    DATA_ROLL                           = 2,
    SNAP_ROLL                           = 3,
};

enum {
    ER_512B_BLOCKSIZE                   = 0,
    ER_2KiB_BLOCKSIZE                   = 1,
    ER_4KiB_BLOCKSIZE                   = 2,
    ER_8KiB_BLOCKSIZE                   = 3,
    ER_16KiB_BLOCKSIZE                  = 4,
    ER_32KiB_BLOCKSIZE                  = 5,
    ER_64KiB_BLOCKSIZE                  = 6,
};

/* Encryption Rolling Flags */
#define ERSB_FLAG_ENCRYPTING            0x00000001
#define ERSB_FLAG_DECRYPTING            0x00000002
#define ERSB_FLAG_KEYROLLING            0x00000004
#define ERSB_FLAG_PAUSED                0x00000008
#define ERSB_FLAG_FAILED                0x00000010
#define ERSB_FLAG_CID_IS_TWEAK          0x00000020
#define ERSB_FLAG_FREE_1                0x00000040
#define ERSB_FLAG_FREE_2                0x00000080

#define ERSB_FLAG_CM_BLOCK_SIZE_MASK    0x00000F00
#define ERSB_FLAG_CM_BLOCK_SIZE_SHIFT   8

#define ERSB_FLAG_ER_PHASE_MASK         0x00003000
#define ERSB_FLAG_ER_PHASE_SHIFT        12
#define ERSB_FLAG_FROM_ONEKEY           0x00004000

/* Encryption Rolling Constants */
#define ER_CHECKSUM_LENGTH              8
#define ER_MAGIC                        b'FLAB'
#define ER_VERSION                      1

#define ER_MAX_CHECKSUM_COUNT_SHIFT     16
#define ER_CUR_CHECKSUM_COUNT_MASK      0x0000FFFF

struct er_state_phys_header {
    obj_phys_t  ersb_o;
    uint32_t    ersb_magic;
    uint32_t    ersb_version;
};
typedef struct er_state_phys_header er_state_phys_header_t;

struct er_state_phys {
    er_state_phys_header_t  ersb_header;
    uint64_t    ersb_flags;
    uint64_t    ersb_snap_xid;
    uint64_t    ersb_current_fext_obj_id;
    uint64_t    ersb_file_offset;
    uint64_t    ersb_progress;
    uint64_t    ersb_total_blk_to_encrypt;
    oid_t       ersb_blockmap_oid;
    uint64_t    ersb_tidemark_obj_id;
    uint64_t    ersb_recovery_extents_count;
    oid_t       ersb_recovery_list_oid;
    uint64_t    ersb_recovery_length;
};
typedef struct er_state_phys er_state_phys_t;

struct er_state_phys_v1 {
    er_state_phys_header_t  ersb_header;
    uint64_t    ersb_flags;
    uint64_t    ersb_snap_xid;
    uint64_t    ersb_current_fext_obj_id;
    uint64_t    ersb_file_offset;
    uint64_t    ersb_fext_pbn;
    uint64_t    ersb_paddr;
    uint64_t    ersb_progress;
    uint64_t    ersb_total_blk_to_encrypt;
    uint64_t    ersb_blockmap_oid;
    uint32_t    ersb_checksum_count;
    uint32_t    ersb_reserved;
    uint64_t    ersb_fext_cid;
    uint8_t     ersb_checksum[0];
};
typedef struct er_state_phys_v1 er_state_phys_v1_t;

struct er_recovery_block_phys {
    obj_phys_t  erb_o;
    uint64_t    erb_offset;
    oid_t       erb_next_oid;
    char        erb_data[0];
};
typedef struct er_recovery_block_phys er_recovery_block_phys_t;

struct gbitmap_block_phys {
    obj_phys_t  bmb_o;
    uint64_t    bmb_field[0];
};
typedef struct gbitmap_block_phys gbitmap_block_phys_t;

struct gbitmap_phys {
    obj_phys_t  bm_o;
    oid_t       bm_tree_oid;
    uint64_t    bm_bit_count;
    uint64_t    bm_flags;
};
typedef struct gbitmap_phys gbitmap_phys_t;

/*
 * EFI Jumpstart
 */

#define NX_EFI_JUMPSTART_MAGIC          b'RDSJ'
#define NX_EFI_JUMPSTART_VERSION        1

struct nx_efi_jumpstart {
    obj_phys_t  nej_o;
    uint32_t    nej_magic;
    uint32_t    nej_version;
    uint32_t    nej_efi_file_len;
    uint32_t    nej_num_extents;
    uint64_t    nej_reserved[16];
    prange_t    nej_rec_extents[];
};
typedef struct nx_efi_jumpstart nx_efi_jumpstart_t;

/*
 * Container
 */

#define NX_MAGIC                        b'BSXN'
#define NX_MAX_FILE_SYSTEMS             100
#define NX_EPH_INFO_COUNT               4
#define NX_EPH_MIN_BLOCK_COUNT          8
#define NX_MAX_FILE_SYSTEM_EPH_STRUCTS  4
#define NX_TX_MIN_CHECKPOINT_COUNT      4
#define NX_EPH_INFO_VERSION_1           1

#define NX_MINIMUM_BLOCK_SIZE           4096
#define NX_DEFAULT_BLOCK_SIZE           4096
#define NX_MAXIMUM_BLOCK_SIZE           65536
#define NX_MINIMUM_CONTAINER_SIZE       1048576

#define NX_RESERVED_1                   0x00000001
#define NX_RESERVED_2                   0x00000002
#define NX_CRYPTO_SW                    0x00000004

flag NX_FEATURE {
    DEFRAG                              = 0x0000000000000001,
    LCFD                                = 0x0000000000000002,
};

flag NX_INCOMPAT {
    VERSION1                            = 0x0000000000000001,
    VERSION2                            = 0x0000000000000002,
    FUSION                              = 0x0000000000000100,
};

enum {
    NX_CNTR_OBJ_CKSUM_SET               = 0,
    NX_CNTR_OBJ_CKSUM_FAIL              = 1,
    NX_NUM_COUNTERS                     = 32,
};

struct nx_superblock {
    obj_phys_t  nx_o;
    uint32_t    nx_magic;
    uint32_t    nx_block_size;
    uint64_t    nx_block_count;
    uint64_t    nx_features;
    uint64_t    nx_readonly_compatible_features;
    uint64_t    nx_incompatible_features;
    char        nx_uuid[16];
    oid_t       nx_next_oid;
    xid_t       nx_next_xid;
    uint32_t    nx_xp_desc_blocks;
    uint32_t    nx_xp_data_blocks;
    paddr_t     nx_xp_desc_base;
    paddr_t     nx_xp_data_base;
    uint32_t    nx_xp_desc_next;
    uint32_t    nx_xp_data_next;
    uint32_t    nx_xp_desc_index;
    uint32_t    nx_xp_desc_len;
    uint32_t    nx_xp_data_index;
    uint32_t    nx_xp_data_len;
    oid_t       nx_spaceman_oid;
    oid_t       nx_omap_oid;
    oid_t       nx_reaper_oid;
    uint32_t    nx_test_type;
    uint32_t    nx_max_file_systems;
    oid_t       nx_fs_oid[NX_MAX_FILE_SYSTEMS];
    uint64_t    nx_counters[NX_NUM_COUNTERS];
    prange_t    nx_blocked_out_prange;
    oid_t       nx_evict_mapping_tree_oid;
    uint64_t    nx_flags;
    paddr_t     nx_efi_jumpstart;
    char        nx_fusion_uuid[16];
    prange_t    nx_keylocker;
    uint64_t    nx_ephemeral_info[NX_EPH_INFO_COUNT];
    oid_t       nx_test_oid;
    oid_t       nx_fusion_mt_oid;
    oid_t       nx_fusion_wbc_oid;
    prange_t    nx_fusion_wbc;
    uint64_t    nx_newest_mounted_version;
    prange_t    nx_mkb_locker;
};

#define CHECKPOINT_MAP_LAST             0x00000001

struct checkpoint_mapping {
    uint32_t    cpm_type;
    uint32_t    cpm_subtype;
    uint32_t    cpm_size;
    uint32_t    cpm_pad;
    oid_t       cpm_fs_oid;
    oid_t       cpm_oid;
    oid_t       cpm_paddr;
};
typedef struct checkpoint_mapping checkpoint_mapping_t;

struct checkpoint_map_phys {
    obj_phys_t              cpm_o;
    uint32_t                cpm_flags;
    uint32_t                cpm_count;
    checkpoint_mapping_t    cpm_map[cpm_count];
};
typedef struct checkpoint_map_phys checkpoint_map_phys_t;

struct evict_mapping_val {
    paddr_t     dst_paddr;
    uint64_t    len;
};
typedef struct evict_mapping_val evict_mapping_val_t;

/*
 * Volume
 */

#define APFS_MAGIC                      b'BSPA'
#define APFS_MAX_HIST                   8
#define APFS_VOLNAME_LEN                256

#define APFS_MODIFIED_NAMELEN           32

struct apfs_modified_by {
    char        id[APFS_MODIFIED_NAMELEN];
    uint64_t    timestamp;
    xid_t       last_xid;
};
typedef struct apfs_modified_by apfs_modified_by_t;

struct apfs_superblock {
    obj_phys_t  apfs_o;
    uint32_t    apfs_magic;
    uint32_t    apfs_fs_index;
    uint64_t    apfs_features;
    uint64_t    apfs_readonly_compatible_features;
    uint64_t    apfs_incompatible_features;
    uint64_t    apfs_unmount_time;
    uint64_t    apfs_fs_reserve_block_count;
    uint64_t    apfs_fs_quota_block_count;
    uint64_t    apfs_fs_alloc_count;
    wrapped_meta_crypto_state_t apfs_meta_crypto;
    uint32_t    apfs_root_tree_type;
    uint32_t    apfs_extentref_tree_type;
    uint32_t    apfs_snap_meta_tree_type;
    oid_t       apfs_omap_oid;
    oid_t       apfs_root_tree_oid;
    oid_t       apfs_extentref_tree_oid;
    oid_t       apfs_snap_meta_tree_oid;
    xid_t       apfs_revert_to_xid;
    oid_t       apfs_revert_to_sblock_oid;
    uint64_t    apfs_next_obj_id;
    uint64_t    apfs_num_files;
    uint64_t    apfs_num_directories;
    uint64_t    apfs_num_symlinks;
    uint64_t    apfs_num_other_fsobjects;
    uint64_t    apfs_num_snapshots;
    uint64_t    apfs_total_blocks_alloced;
    uint64_t    apfs_total_blocks_freed;
    char        apfs_vol_uuid[16];
    uint64_t    apfs_last_mod_time;
    uint64_t    apfs_fs_flags;
    apfs_modified_by_t  apfs_formatted_by;
    apfs_modified_by_t  apfs_modified_by[APFS_MAX_HIST];
    char        apfs_volname[APFS_VOLNAME_LEN];
    uint32_t    apfs_next_doc_id;
    uint16_t    apfs_role;
    uint16_t    reserved;
    xid_t       apfs_root_to_xid;
    oid_t       apfs_er_state_oid;
    uint64_t    apfs_cloneinfo_id_epoch;
    xid_t       apfs_cloneinfo_xid;
    oid_t       apfs_snap_meta_ext_oid;
    char        apfs_volume_group_id[16];
    oid_t       apfs_integrity_meta_oid;
    oid_t       apfs_fext_tree_oid;
    uint32_t    apfs_fext_tree_type;
    uint32_t    apfs_pfkur_tree_type;
    oid_t       apfs_pfkur_tree_oid;
    // Undocumented from here on
    xid_t       apfs_doc_id_index_xid;
    uint32_t    apfs_doc_id_index_flags;
    uint32_t    apfs_doc_id_tree_type;
    oid_t       apfs_doc_id_tree_oid;
    oid_t       apfs_prev_doc_id_tree_oid;
    uint64_t    apfs_doc_id_fixup_cursor;
    oid_t       apfs_sec_root_tree_oid;
    uint32_t    apfs_sec_root_tree_type;
    uint32_t    apfs_clone_group_tree_flags;
};
typedef struct apfs_superblock apfs_superblock_t;

flag APFS_FEATURE {
    DEFRAG_PRERELEASE                   = 0x00000001,
    HARDLINK_MAP_RECORDS                = 0x00000002,
    DEFRAG                              = 0x00000004,
    STRICTATIME                         = 0x00000008,
    VOLGRP_SYSTEM_INO_SPACE             = 0x00000010,
};

flag APFS_INCOMPAT {
    CASE_INSENSITIVE                    = 0x00000001,
    DATALESS_SNAPS                      = 0x00000002,
    ENC_ROLLED                          = 0x00000004,
    NORMALIZATION_INSENSITIVE           = 0x00000008,
    INCOMPLETE_RESTORE                  = 0x00000010,
    SEALED_VOLUME                       = 0x00000020,
    PFK                                 = 0x00000040,   // Undocumented name
    RESERVED_80                         = 0x00000080,   // Maybe EXTENT_PREALLOC according to linux-apfs-rw
    SECONDARY_FSROOT                    = 0x00000100,   // Undocumented name
};

#define APFS_VOLUME_ENUM_SHIFT          6

flag APFS_FS {
    UNENCRYPTED                         = 0x00000001,
    RESERVED_2                          = 0x00000002,
    RESERVED_4                          = 0x00000004,
    ONEKEY                              = 0x00000008,
    SPILLEDOVER                         = 0x00000010,
    RUN_SPILLOVER_CLEANER               = 0x00000020,
    ALWAYS_CHECK_EXTENTREF              = 0x00000040,
    PREVIOUSLY_SEALED                   = 0x00000080,   // Undocumented name
    PFK                                 = 0x00000100,   // Undocumented name
    RESERVED_200                        = 0x00000200,
    RESERVED_400                        = 0x00000400,
    RESERVED_800                        = 0x00000800,
};

enum APFS_VOL_ROLE {
    NONE                                = 0x0000,
    SYSTEM                              = 0x0001,
    USER                                = 0x0002,
    RECOVERY                            = 0x0004,
    VM                                  = 0x0008,
    PREBOOT                             = 0x0010,
    INSTALLER                           = 0x0020,
    DATA                                = (1 << APFS_VOLUME_ENUM_SHIFT),
    BASEBAND                            = (2 << APFS_VOLUME_ENUM_SHIFT),
    UPDATE                              = (3 << APFS_VOLUME_ENUM_SHIFT),
    XART                                = (4 << APFS_VOLUME_ENUM_SHIFT),
    HARDWARE                            = (5 << APFS_VOLUME_ENUM_SHIFT),
    BACKUP                              = (6 << APFS_VOLUME_ENUM_SHIFT),
    RESERVED_7                          = (7 << APFS_VOLUME_ENUM_SHIFT),
    RESERVED_8                          = (8 << APFS_VOLUME_ENUM_SHIFT),
    ENTERPRISE                          = (9 << APFS_VOLUME_ENUM_SHIFT),
    RESERVED_10                         = (10 << APFS_VOLUME_ENUM_SHIFT),
    PRELOGIN                            = (11 << APFS_VOLUME_ENUM_SHIFT),
};

/*
 * Sealed Volumes
 */

enum apfs_hash_type_t : uint32_t {
    APFS_HASH_INVALID                   = 0,
    APFS_HASH_SHA256                    = 0x1,
    APFS_HASH_SHA512_256                = 0x2,
    APFS_HASH_SHA384                    = 0x3,
    APFS_HASH_SHA512                    = 0x4,
};

#define APFS_HASH_CCSHA256_SIZE         32
#define APFS_HASH_CCSHA512_256_SIZE     32
#define APFS_HASH_CCSHA384_SIZE         48
#define APFS_HASH_CCSHA512_SIZE         64

#define APFS_HASH_MAX_SIZE              64

struct integrity_meta_phys {
    obj_phys_t          im_o;
    uint32_t            im_version;
    uint32_t            im_flags;
    apfs_hash_type_t    im_hash_type;
    uint32_t            im_root_hash_offset;
    xid_t               im_broken_xid;
    uint64_t            im_reserved[9];
};
typedef struct integrity_meta_phys integrity_meta_phys_t;

/* Integrity Metadata Flags */
#define APFS_SEAL_BROKEN                (1 << 0)

struct fext_tree_key {
    uint64_t    private_id;
    uint64_t    logical_addr;
};
typedef struct fext_tree_key fext_tree_key_t;

struct fext_tree_val {
    uint64_t    len_and_flags;
    uint64_t    phys_block_num;
};
typedef struct fext_tree_val fext_tree_val_t;

struct j_file_info_key {
    j_key_t     hdr;
    uint64_t    info_and_lba;
};
typedef struct j_key_t j_file_info_key_t;

#define J_FILE_INFO_LBA_MASK            0x00ffffffffffffff
#define J_FILE_INFO_TYPE_MASK           0xff00000000000000
#define J_FILE_INFO_TYPE_SHIFT          56

struct j_file_data_hash_val {
    uint16_t    hashed_len;
    uint8_t     hash_size;
    char        hash[hash_size];
};
typedef struct j_file_data_hash_val j_file_data_hash_val_t;

struct j_file_info_val {
    union {
        j_file_data_hash_val_t dhash;
    };
};
typedef struct j_file_data_hash_val_t j_file_info_val_t;

enum APFS_FILE_INFO {
    DATA_HASH                           = 1,
};
/* typedef enum j_obj_file_info_type; */

/*
 * Space Manager
 */

typedef uint64_t spaceman_free_queue_val_t;

#define SM_ALLOCZONE_INVALID_END_BOUNDARY       0
#define SM_ALLOCZONE_NUM_PREVIOUS_BOUNDARIES    7

#define SM_DATAZONE_ALLOCZONE_COUNT     8

#define SM_FLAG_VERSIONED               0x00000001

enum {
    SFQ_IP                              = 0,
    SFQ_MAIN                            = 1,
    SFQ_TIER2                           = 2,
    SFQ_COUNT                           = 3
};

enum {
    SD_MAIN                             = 0,
    SD_TIER2                            = 1,
    SD_COUNT                            = 2
};

/* Chunk Info Block Constants */
#define CI_COUNT_MASK                   0x000fffff
#define CI_COUNT_RESERVED_MASK          0xfff00000

/* Internal-Pool Bitmap */
#define SPACEMAN_IP_BM_TX_MULTIPLIER    16
#define SPACEMAN_IP_BM_INDEX_INVALID    0xffff
#define SPACEMAN_IP_BM_BLOCK_COUNT_MAX  0xfffe

struct chunk_info {
    uint64_t    ci_xid;
    uint64_t    ci_addr;
    uint32_t    ci_block_count;
    uint32_t    ci_free_count;
    paddr_t     ci_bitmap_addr;
};
typedef struct chunk_info chunk_info_t;

struct chunk_info_block {
    obj_phys_t      cib_o;
    uint32_t        cib_index;
    uint32_t        cib_chunk_info_count;
    chunk_info_t    cib_chunk_info[cib_chunk_info_count];
};
typedef struct chunk_info_block chunk_info_block_t;

struct cib_addr_block {
    obj_phys_t  cab_o;
    uint32_t    cab_index;
    uint32_t    cab_cib_count;
    paddr_t     cab_cib_addr[cab_cib_count];
};
typedef struct cib_addr_block cib_addr_block_t;

struct spaceman_free_queue_key {
    xid_t       sfqk_xid;
    paddr_t     sfqk_paddr;
};
typedef struct spaceman_free_queue_key spaceman_free_queue_key_t;

struct spaceman_free_queue_entry {
    spaceman_free_queue_key_t   sfqe_key;
    spaceman_free_queue_val_t   sfqe_count;
};
typedef struct spaceman_free_queue_entry spaceman_free_queue_entry_t;

struct spaceman_free_queue {
    uint64_t    sfq_count;
    oid_t       sfq_tree_oid;
    xid_t       sfq_oldest_xid;
    uint16_t    sfq_tree_node_limit;
    uint16_t    sfq_pad16;
    uint32_t    sfq_pad32;
    uint64_t    sfq_reserved;
};
typedef struct spaceman_free_queue spaceman_free_queue_t;

struct spaceman_device {
    uint64_t    sm_block_count;
    uint64_t    sm_chunk_count;
    uint32_t    sm_cib_count;
    uint32_t    sm_cab_count;
    uint64_t    sm_free_count;
    uint32_t    sm_addr_offset;
    uint32_t    sm_reserved;
    uint64_t    sm_reserved2;
};
typedef struct spaceman_device spaceman_device_t;

struct spaceman_allocation_zone_boundaries {
    uint64_t    saz_zone_start;
    uint64_t    saz_zone_end;
};
typedef struct spaceman_allocation_zone_boundaries spaceman_allocation_zone_boundaries_t;

struct spaceman_allocation_zone_info_phys {
    spaceman_allocation_zone_boundaries_t   saz_current_boundaries;
    spaceman_allocation_zone_boundaries_t   saz_previous_boundaries[SM_ALLOCZONE_NUM_PREVIOUS_BOUNDARIES];
    uint16_t    saz_zone_id;
    uint16_t    saz_previous_boundary_index;
    uint32_t    saz_reserved;
};
typedef struct spaceman_allocation_zone_info_phys spaceman_allocation_zone_info_phys_t;

struct spaceman_datazone_info_phys {
    spaceman_allocation_zone_info_phys_t    sdz_allocation_zones[SD_COUNT][SM_DATAZONE_ALLOCZONE_COUNT];
};
typedef struct spaceman_datazone_info_phys spaceman_datazone_info_phys_t;

struct spaceman_phys {
    obj_phys_t  sm_o;
    uint32_t    sm_block_size;
    uint32_t    sm_blocks_per_chunk;
    uint32_t    sm_chunks_per_cib;
    uint32_t    sm_cibs_per_cab;
    spaceman_device_t   sm_dev[SD_COUNT];
    uint32_t    sm_flags;
    uint32_t    sm_ip_bm_tx_multiplier;
    uint64_t    sm_ip_block_count;
    uint32_t    sm_ip_bm_size_in_blocks;
    uint32_t    sm_ip_bm_block_count;
    paddr_t     sm_ip_bm_base;
    paddr_t     sm_ip_base;
    uint64_t    sm_fs_reserve_block_count;
    uint64_t    sm_fs_reserve_alloc_count;
    spaceman_free_queue_t   sm_fq[SFQ_COUNT];
    uint16_t    sm_ip_bm_free_head;
    uint16_t    sm_ip_bm_free_tail;
    uint32_t    sm_ip_bm_xid_offset;
    uint32_t    sm_ip_bitmap_offset;
    uint32_t    sm_ip_bm_free_next_offset;
    uint32_t    sm_version;
    uint32_t    sm_struct_size;
    spaceman_datazone_info_phys_t   sm_datazone;
};
typedef struct spaceman_phys spaceman_phys_t;

/*
 * Reaper
 */

/* Volume Reaper States */
enum APFS_REAP_PHASE {
    START                               = 0,
    SNAPSHOTS                           = 1,
    ACTIVE_FS                           = 2,
    DESTROY_OMAP                        = 3,
    DONE                                = 4
};

/* Reaper Flags */
#define NR_BHM_FLAG                     0x00000001
#define NR_CONTINUE                     0x00000002

/* Reaper List Entry Flags */
#define NRLE_VALID                      0x00000001
#define NRLE_REAP_ID_RECORD             0x00000002
#define NRLE_CALL                       0x00000004
#define NRLE_COMPLETION                 0x00000008
#define NRLE_CLEANUP                    0x00000010

/* Reaper List Flags */
#define NRL_INDEX_INVALID               0xffffffff

struct nx_reaper_phys {
    obj_phys_t  nr_o;
    uint64_t    nr_next_reap_id;
    uint64_t    nr_completed_id;
    oid_t       nr_head;
    oid_t       nr_tail;
    uint32_t    nr_flags;
    uint32_t    nr_rlcount;
    uint32_t    nr_type;
    uint32_t    nr_size;
    oid_t       nr_fs_oid;
    oid_t       nr_oid;
    xid_t       nr_xid;
    uint32_t    nr_nrle_flags;
    uint32_t    nr_state_buffer_size;
    uint8_t     nr_state_buffer[];
};
typedef struct nx_reaper_phys nx_reaper_phys_t;

struct nx_reap_list_entry {
    uint32_t    nrle_next;
    uint32_t    nrle_flags;
    uint32_t    nrle_type;
    uint32_t    nrle_size;
    oid_t       nrle_fs_oid;
    oid_t       nrle_oid;
    xid_t       nrle_xid;
};
typedef struct nx_reap_list_entry nx_reap_list_entry_t;

struct nx_reap_list_phys {
    obj_phys_t  nrl_o;
    oid_t       nrl_next;
    uint32_t    nrl_flags;
    uint32_t    nrl_max;
    uint32_t    nrl_count;
    uint32_t    nrl_first;
    uint32_t    nrl_last;
    uint32_t    nrl_free;
    // nx_reap_list_entry_t    nrl_entries[];
};
typedef struct nx_reap_list_phys nx_reap_list_phys_t;

struct omap_reap_state {
    uint32_t    omr_phase;
    omap_key_t  omr_ok;
};
typedef struct omap_reap_state omap_reap_state_t;

struct omap_cleanup_state {
    uint32_t    omc_cleaning;
    uint32_t    omc_omsflags;
    xid_t       omc_sxidprev;
    xid_t       omc_sxidstart;
    xid_t       omc_sxidend;
    xid_t       omc_sxidnext;
    omap_key_t  omc_curkey;
};
typedef struct omap_cleanup_state omap_cleanup_state_t;

struct apfs_reap_state {
    uint64_t    last_pbn;
    xid_t       cur_snap_xid;
    uint32_t    phase;
};
typedef struct apfs_reap_state apfs_reap_state_t;

/*
 * Fusion
 */

typedef paddr_t fusion_mt_key_t;

#define FUSION_TIER2_DEVICE_BYTE_ADDR   0x4000000000000000

struct fusion_wbc_phys {
    obj_phys_t  fwp_objHdr;
    uint64_t    fwp_version;
    oid_t       fwp_listHeadOid;
    oid_t       fwp_listTailOid;
    uint64_t    fwp_stableHeadOffset;
    uint64_t    fwp_stableTailOffset;
    uint32_t    fwp_listBlocksCount;
    uint32_t    fwp_reserved;
    uint64_t    fwp_usedByRC;
    prange_t    fwp_rcStash;
};
typedef struct fusion_wbc_phys fusion_wbc_phys_t;

struct fusion_wbc_list_entry {
    paddr_t     fwle_wbcLba;
    paddr_t     fwle_targetLba;
    uint64_t    fwle_length;
};
typedef struct fusion_wbc_list_entry fusion_wbc_list_entry_t;

struct fusion_wbc_list_phys {
    obj_phys_t  fwlp_objHdr;
    uint64_t    fwlp_version;
    uint64_t    fwlp_tailOffset;
    uint32_t    fwlp_indexBegin;
    uint32_t    fwlp_indexEnd;
    uint32_t    fwlp_indexMax;
    uint32_t    fwlp_reserved;
    fusion_wbc_list_entry_t     fwlp_listEntries[];
};
typedef struct fusion_wbc_list_phys fusion_wbc_list_phys_t;

struct fusion_mt_val {
    paddr_t     fmv_lba;
    uint32_t    fmv_length;
    uint32_t    fmv_flags;
};
typedef struct fusion_mt_val fusion_mt_val_t;

#define FUSION_MT_DIRTY                 (1 << 0)
#define FUSION_MT_TENANT                (1 << 1)
#define FUSION_MT_ALLFLAGS              (FUSION_MT_DIRTY | FUSION_MT_TENANT)
"""
c_apfs = cstruct()
c_apfs.load(apfs_def)

FILESYSTEM_OBJECT_TYPE_MAP = {
    c_apfs.APFS_TYPE.SNAP_METADATA: (c_apfs.j_snap_metadata_key, c_apfs.j_snap_metadata_val),
    c_apfs.APFS_TYPE.EXTENT: (c_apfs.j_phys_ext_key, c_apfs.j_phys_ext_val),
    c_apfs.APFS_TYPE.INODE: (c_apfs.j_inode_key, c_apfs.j_inode_val),
    c_apfs.APFS_TYPE.XATTR: (c_apfs.j_xattr_key, c_apfs.j_xattr_val),
    c_apfs.APFS_TYPE.SIBLING_LINK: (c_apfs.j_sibling_key, c_apfs.j_sibling_val),
    c_apfs.APFS_TYPE.DSTREAM_ID: (c_apfs.j_dstream_id_key, c_apfs.j_dstream_id_val),
    c_apfs.APFS_TYPE.CRYPTO_STATE: (c_apfs.j_crypto_key, c_apfs.j_crypto_val),
    c_apfs.APFS_TYPE.FILE_EXTENT: (c_apfs.j_file_extent_key, c_apfs.j_file_extent_val),
    c_apfs.APFS_TYPE.DIR_REC: (c_apfs.j_drec_hashed_key, c_apfs.j_drec_val),
    c_apfs.APFS_TYPE.DIR_STATS: (c_apfs.j_dir_stats_key, c_apfs.j_dir_stats_val),
    c_apfs.APFS_TYPE.SNAP_NAME: (c_apfs.j_snap_name_key, c_apfs.j_snap_name_val),
    c_apfs.APFS_TYPE.SIBLING_MAP: (c_apfs.j_sibling_map_key, c_apfs.j_sibling_map_val),
    c_apfs.APFS_TYPE.FILE_INFO: (c_apfs.j_file_info_key, c_apfs.j_file_info_val),
}

XF_MAP = {
    c_apfs.DREC_EXT_TYPE.SIBLING_ID: c_apfs.uint64_t,
    c_apfs.INO_EXT_TYPE.SNAP_XID: c_apfs.xid_t,
    c_apfs.INO_EXT_TYPE.DELTA_TREE_OID: c_apfs.oid_t,
    c_apfs.INO_EXT_TYPE.DOCUMENT_ID: c_apfs.uint32_t,
    c_apfs.INO_EXT_TYPE.PREV_FSIZE: c_apfs.uint64_t,
    c_apfs.INO_EXT_TYPE.DSTREAM: c_apfs.j_dstream,
    c_apfs.INO_EXT_TYPE.DIR_STATS_KEY: c_apfs.j_dir_stats_val,
    c_apfs.INO_EXT_TYPE.SPARSE_BYTES: c_apfs.uint64_t,
    c_apfs.INO_EXT_TYPE.RDEV: c_apfs.uint32_t,
}
