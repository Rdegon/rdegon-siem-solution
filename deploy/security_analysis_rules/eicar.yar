rule EICAR_Antivirus_Test_File
{
  meta:
    description = "Detect the standard EICAR antivirus test string"
    source = "EICAR"
  strings:
    $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
  condition:
    $eicar
}
