# Invoke-BitsParser
A few scripts I have written to parse various Windows Background Intelligent Transfer Service (BITS) artefacts.

### Invoke-BitsParser.ps1
* Parses BITS jobs from QMGR files.
* QMGR files are named qmgr0.dat or qmgr1.dat and located in the folder %ALLUSERSPROFILE%\Microsoft\Network\Downloader.
* Capable to run in live mode or against precollected files.
* Initial Python parser used as inspiration by ANSSI here - https://github.com/ANSSI-FR/bits_parser
* Invoke-BitsParser currently does not carve non complete jobs.
* Currently not supported on Windows 10+

### Invoke-BitsTransfer.ps1
*  carves BITS file transfer details from QMGR files.
* QMGR files are named qmgr0.dat or qmgr1.dat and located in the folder %ALLUSERSPROFILE%\Microsoft\Network\Downloader.
* Finding XferHeaders, Invoke-BitsTransfer then searches for valid paths.
* Run to carve all File transfer information - Source and Destination. Then look for unusual entries.
* Currently not supported on Windows 10 with different formatting.

### Invoke-BitsDetection.ps1 
* Extracts all BITS transfer URLs from Windows BITS Event log.
* Microsoft-Windows-Bits-Client/Operational Event ID 59.
* Whitelist of commonly used domains, please add new domains.
* The goal of this script is to detect anomolous sources for BITs transfers that can lead to additional investigation.
* Use -All switch to list all URL sources and do not run Whitleist check.

