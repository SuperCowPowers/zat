rule backoff

{
	strings:
		$1a = "Undsa8301nskal"
		$1b = "PasswordUndsa8301nskal"
		$1c = "Download and Run"
		$1d = "Upload KeyLogs"
		
		$2a = "User-Agent: Mozilla/5.0 (Windows NT 6.1; rv:24.0) Gecko/20100101 Firefox/24.0"

		$3a = "\\AdobeFlashPlayer\\mswinhost.exe" //Install Path
		$3b = "\\AdobeFlashPlayer\\mswinsvc.exe" //Install Path
		$3c = "\\OracleJava\\javaw.exe" //Install Path

		$4a = "\\AdobeFlashPlayer\\Local.dat"
		$4b = "\\AdobeFlashPlayer\\Log.txt"

		$5a = "uhYtntr56uisGst" //Mutex
		$5b = "uyhnJmkuTgD" //Mutex
		$5c = "Undsa8301nskal" //Mutex

		$6a = "zXqW9JdWLM4urgjRkX" //Post String
		$6b = "jhgtsd7fjmytkr" //POST String
		$6c = "ihasd3jasdhkas9" //Post String

		$7a = "/aircanada/dark.php" //URI Path
		$7b = "/aero2/fly.php" //URI Path
		$7c = "/windows/updcheck.php" //URI Path
		$7d = "/windowsxp/updcheck.php" //URI Path
		$7e = "/windebug/updcheck.php" //URI Path
		$7f = "/hello/flash.php" //URI Path

	condition:
		any of them

}
