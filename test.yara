import "hash"

rule Control32 {
    meta:
        author = "Jaume Martin"
    condition:
        hash.sha256(0, filesize) == "da2a4e7e5748f929058fd654aaf1890c80909b08c90bbdc2a12bfcf2efee1cea"
}

