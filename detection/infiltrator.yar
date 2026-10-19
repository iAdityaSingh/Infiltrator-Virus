rule Infiltrator_Lab_Source
{
    meta:
        description = "Flags source files of the Infiltrator Lab training project"
        author = "Infiltrator Lab"
        purpose = "Training: practise writing and testing YARA"
    strings:
        $banner  = "INFILTRATOR LAB" ascii nocase
        $subject = "[INFLTR-SIM] Synthetic lab report" ascii
        $evtype  = "SIM_INPUT_ACTIVITY" ascii
        $nettype = "SIM_NETWORK_CONNECTION" ascii
    condition:
        any of them
}

rule Infiltrator_Lab_Log_Artifact
{
    meta:
        description = "Flags synthetic event/network logs produced by the lab"
    strings:
        $s1 = "\"synthetic\":true" ascii
        $s2 = "SIM_INPUT_ACTIVITY" ascii
        $s3 = "SIM_NETWORK_CONNECTION" ascii
    condition:
        2 of them
}
