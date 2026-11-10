// Accepted but expensive: many matches of a short, common pattern. Used to verify
// that the per-pattern match cap and the scan deadline bound rule evaluation.
rule RaxoHeavyMatches
{
    strings:
        $a = "AAAA"
        $re = /A{4}[A-Z]{0,64}B/
    condition:
        #a > 1000000 or $re
}
