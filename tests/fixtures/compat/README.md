# Compatibility fixtures

From oscal-ssp-generator at commit bd12541: its example `terraform.tfstate`, and the
SSP it generates from that file. The test checks that boundary-drift-detector reads
that SSP's inventory and finds no drift against the same state.
