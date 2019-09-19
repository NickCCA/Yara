import "hash"

rule Mainfile {
    meta:
        author = "Jaume Martin"
    condition:
        hash.md5(0, filesize) == "dca1e81ae7656f0a52408dea3854a42a"
}

rule actsus
{
    meta:
        author = "Nick"
        
    strings:
        $a = "ACTSUS.EXE" nocase
        $b = "actsus.exe" wide
        $c = "actsus" wide

    condition:
    1 of them
}
