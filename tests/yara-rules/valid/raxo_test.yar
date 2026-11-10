// Controlled RaxoSentinel test rules. They match only synthetic markers created by
// tests/attachment-corpus/generate.py and carry no third-party intelligence.

rule RaxoTestMarker
{
    meta:
        description = "Synthetic RaxoSentinel YARA-X test marker"
        severity = "high"
        detection_type = "deterministic"
    strings:
        $marker = "RAXO-YARA-TEST-MARKER-7f3c9e"
    condition:
        $marker
}

rule RaxoTestHexSequence
{
    meta:
        description = "Synthetic byte sequence with a wildcard"
        severity = "medium"
    strings:
        $seq = { 52 41 58 4F ?? 48 45 58 2D 31 39 37 33 }
    condition:
        $seq
}
