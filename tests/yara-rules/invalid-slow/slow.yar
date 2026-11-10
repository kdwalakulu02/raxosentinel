// Rejected: a regular expression with no usable atoms would scan every byte.
rule RaxoSlowPattern
{
    strings:
        $any = /[\x00-\xff]{2,}/
    condition:
        $any
}
