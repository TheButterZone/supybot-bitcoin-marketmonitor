# Thanks to TheButterZone (16193nPH2mS3Q5U2Ui9HMLPxmxR9r4wxu3) for this script!
# This works under OSX 10.6.8-10.15.8, Adium 1.5.*, Electrum 4.5.8
# There are 3 fields you need to replace: 
# YOURNICKGOESHERE, YOURWALLETFILEPATHHERE, YOUROTCBTCADDRESS
# Once you edit this script to your unique specs, save it as a run-only application.
# Only run this when Adium is already logged into IRC.

-- 0. Request OTP to Bitcoin sign
tell application "Adium"
	activate
	send the active chat message "/join #gribble"
	delay 2
	send the active chat message "/msg gribble bcauth YOURNICKGOESHERE"
end tell
delay 10

-- 1. Securely collect inputs via AppleScript (No terminal prompts)
set theMsg to text returned of (display dialog "Enter message to sign:" default answer "")
set thePass to text returned of (display dialog "Enter wallet password:" default answer "" with hidden answer)

-- 2. Define your paths (Verify these are correct)
set electrumPath to "/Applications/Electrum.app/Contents/MacOS/run_electrum"
set walletPath to "YOURWALLETFILEPATHHERE"
set btcAddress to "YOUROTCBTCADDRESS"

-- 3. Execute in the background to keep the clipboard 100% clean
try
	set shellCmd to "printf %s " & quoted form of theMsg & " | " & electrumPath & " -o -w " & quoted form of walletPath & " signmessage " & btcAddress & " - -W " & quoted form of thePass
	set sig to do shell script shellCmd
	
	-- Strip any extra whitespace and copy to clipboard
	do shell script "printf %s " & quoted form of sig & " | pbcopy"
	display notification "Signature copied to clipboard!" with title "Electrum Signer"
on error errorMsg
	display alert "Signing Failed" message errorMsg
end try

--4. Verify that the signature wasn't corrupted (optional, can be deleted)
try
	set verifyCmd to "printf %s " & quoted form of theMsg & " | " & electrumPath & " -o -w " & quoted form of walletPath & " verifymessage " & btcAddress & " " & quoted form of sig & " -"
	set isVerified to do shell script verifyCmd
	if isVerified is "true" then
		display notification "Signature verified and copied!" with title "Electrum Signer"
	else
		display alert "Warning" message "Signature was generated but failed verification."
	end if
on error
	display alert "Verification Error" message "Could not run verification check."
end try

--5. Reduce keystrokes by concatenating the command & the signature
set currentClipboard to (the clipboard)
set the clipboard to "/msg gribble bcverify " & currentClipboard

--6. Final Gribble commands
tell application "Adium" to activate
delay 0.2
tell application "System Events"
	keystroke "v" using {command down}
	delay 0.1
	keystroke return
end tell
tell application "Adium"
	activate
	send the active chat message "/msg gribble voiceme"
end tell
