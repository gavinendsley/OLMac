
tell application "Radar"
	activate
	display dialog "Enter a description of the problem:" buttons {"Cancel", "OK"} default answer Â
		"* SUMMARY 
		Recap the problem title and/or include more descriptive summary information.

* STEPS TO REPRODUCE
1. Setup or prep work
2. Include explicit and accurate steps to reproduce. Do not include extraneous or irrelevant steps.

* RESULTS
Describe your results and how they differed from what you expected.

* REGRESSION
Provide information on steps taken to isolate the problem. Describe circumstances where the problem occurs or does not occur, such as software versions and/or hardware configurations.

* NOTES
Document any additional information that might be useful in resolving the problem, such as references to related problems, leads on diagnosis, screen shots, included attachments, and any workarounds. " with icon 1
	if button returned of result is "OK" then
		set myDescription to text returned of the result as Unicode text
		set myComponentName to "Sync Services"
		set myComponentVersion to "X"
		set myClassificationCode to 4 -- 1=security; 2=crash/hang/data loss; 3=performance; 4=UI/usability; 6=serious; 7=other; 9=feature; 10=enhancement; 12=task;	
		set myReproducibilityCode to 1
		set buildVers to do shell script "sw_vers -buildVersion"
		set ASTID to AppleScript's text item delimiters
		set AppleScript's text item delimiters to "
"
		if first text item of myDescription starts with "* SUMMARY" then
			set myProblemTitle to buildVers & ":" & second text item of myDescription
		else
			set myProblemTitle to buildVers & ":" & first text item of myDescription
		end if
		set AppleScript's text item delimiters to ASTID
		set myPersonID to ""
		set saveNewProb to false -- true or false
		
		NewProblem description myDescription Â
			componentVersion myComponentVersion Â
			componentName myComponentName Â
			reproducibilityCode myReproducibilityCode Â
			originator myPersonID Â
			problemTitle myProblemTitle Â
			classCode myClassificationCode Â
			doSave saveNewProb
		set pID to getProblemID of window 1
		set myResult to AttachFileToProblem problemID pID filePath "~/Library/Application Support/SyncServices/local/syncservices.log"
		delay 1
		set myResult to AttachFileToProblem problemID pID filePath "~/Library/Logs/Sync"
	end if
end tell
