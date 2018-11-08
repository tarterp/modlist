# modlist
Simple Example for finding and parsing PKDDEBUGGER_DATA64PKDDEBUGGER_DATA64. Once upon a time, this was available from KPCR.KdVersionBlock which can be found easily from gs[0].KdversionBlock. Finding PKDEBUGGER_DATA64 can be found with the following method. This driver prints a module list by grabbing the PsLoadedModuleList.

1. Get KernelBase by backing up page by page KPCR.KPRCB.IdleThread, checking each page base if it is the DOS_HEADER, but first validating it isn't a guard page.
2. Find .data section, this is where the PKDDEBUGGER_DATA64 structure will stored
3. Search the .data section for the tag KDBG ('GBDK'). This is the value stored at PKDDEBUGGER_DATA64.header.OwnerTag
4. Get base address of structure and then we have access