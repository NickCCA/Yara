import "hash"

rule Control32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "6051a5337e90e5114db53f25df6e2e08"
}
