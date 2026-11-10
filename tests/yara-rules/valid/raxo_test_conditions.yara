import "math"

// Two markers in the same object; tests multi-string conditions.
rule RaxoTestPair
{
    meta:
        description = "Both halves of a synthetic marker pair"
        severity = "low"
    strings:
        $a = "RAXO-PAIR-LEFT"
        $b = "RAXO-PAIR-RIGHT"
    condition:
        $a and $b
}
