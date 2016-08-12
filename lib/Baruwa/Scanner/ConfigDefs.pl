# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# This file was forked from MailScanner in July 2016.
# Original author, and relevant copyright and licensing information is below:
# :author: Julian Field
# :copyright: Copyright (C) 2002  Julian Field
#

1;

__DATA__
########################################################################
#
# Go through the entire source code, checking wherever any variable is
# used. Ensure they are used in a way that matches their spec.
#
########################################################################

#
# Translation between Internal and External keyword names.
# This lets me use nice brief names internally, and set the
# config file options to names that mean something.
#
# Format:
#    Internal = External
#

[Translation,Translation]

AFilenameRules                  = ArchivesFilenameRules
AFiletypeRules                  = ArchivesFiletypeRules
aallowfilenames                 = ArchivesAllowFilenames
adenyfilemimetypes              = ArchivesDenyFileMIMETypes
adenyfiletypes                  = ArchivesDenyFiletypes
aallowfilemimetypes             = ArchivesAllowFileMIMETypes
aallowfiletypes                 = ArchivesAllowFiletypes
adenyfilenames                  = ArchivesDenyFilenames
addenvfrom			= AddEnvelopeFromHeader
addenvto			= AddEnvelopeToHeader
addmshmac			= AddWatermark
AllowObjectTags			= AllowObjectCodebaseTags
AllowExternal			= AllowExternalMessageBodies
allowmultsigs			= AllowMultipleHTMLSignatures
AllowPartial			= AllowPartialMessages
allowpasszips			= AllowPasswordProtectedArchives
AllowWebBugTags			= AllowWebBugs
assumeisdir			= MissingMailArchiveIs
attachimage			= AttachImageToSignature
attachimagename			= SignatureImageFilename
attachimageinternalname		= SignatureImageImgFilename
attachimagetohtmlonly		= AttachImageToHTMLMessageOnly
AttachmentCharset		= AttachmentEncodingCharset
bayesrebuild			= RebuildBayesEvery
bayeswait			= WaitDuringBayesRebuild
blacklistedishigh		= definitespamishighscoring
BlockEncrypted			= BlockEncryptedMessages
BlockUnencrypted		= BlockUnencryptedMessages
cachetiming			= SpamAssassinCacheTimings
checkmshmac			= CheckWatermarksWithNoSender
checkmshmacskip			= CheckWatermarksToSkipSpamChecks
checkppafilenames		= CheckFilenamesInPasswordProtectedArchives
CheckSAIfOnSpamList		= checkspamassassinifonspamlist
children			= maxchildren
clamavspam			= ClamAVFullMessageScan
cleanheader			= cleanheadervalue
contentmodifysubject		= contentmodifysubject
contentsubjecttext		= contentsubjecttext
criticalqueuesize		= maxnormalqueuesize
dangerscan			= dangerouscontentscanning
deletedcontentmessage		= deletedbadcontentmessagereport
deletedfilenamemessage		= deletedbadfilenamemessagereport
deletedsizemessage		= deletedsizemessagereport
deletedvirusmessage		= deletedvirusmessagereport
deliverdisinfected		= deliverdisinfectedfiles
deliversilent			= stilldeliversilentviruses
dirtyheader			= infectedheadervalue
disarmmodifysubject		= disarmedmodifysubject
disarmsubjecttext		= disarmedsubjecttext
disinfectedheader		= disinfectedheadervalue
disinfectedreporttext		= disinfectedreport
envfromheader			= EnvelopeFromHeader
envtoheader			= EnvelopeToHeader
findphishing			= FindPhishingFraud
fprotd6port			= FpscandPort
getipfromheader			= ReadIPAddressFromReceivedHeader
gsscanner			= UseCustomSpamScanner
gstimeout			= CustomSpamScannerTimeout
gstimeoutlen			= CustomSpamScannertimeouthistory
hamactions                      = nonspamactions
hideworkdir			= hideincomingworkdir
hideworkdirinnotice		= hideincomingworkdirinnotices
highrbls                        = spamliststoreachhighscore
highscorespamactions		= highscoringspamactions
highspammodifysubject		= highscoringspammodifysubject
highspamsubjecttext		= highscoringspamsubjecttext
htmltotext			= converthtmltotext
includespamheader		= alwaysincludespamassassinreport
infoheader			= informationheader
infovalue			= informationheadervalue
insistpasszips			= ArchivesMustBePasswordProtected
inlinehtmlsig			= inlinehtmlsignature
inlinehtmlwarning		= inlinehtmlwarning
inlinetextsig			= inlinetextsignature
inlinetextwarning		= inlinetextwarning
inqueuedir			= incomingqueuedir
ipverheader			= ipprotocolversionheader
isareply			= dontsignhtmlifheadersexist
keepspamarchiveclean		= keepspamarchiveclean
lastafterbatch			= alwayslookeduplastafterbatch
lastlookup			= alwayslookeduplast
listsascores                    = includescoresinspamassassinreport
logdelivery			= logdeliveryandnondelivery
loghtmltags			= logdangeroushtmltags
logfacility			= syslogfacility
logsaactions			= logspamassassinruleactions
logsock				= syslogsockettype
lookforuu			= finduuencodedfiles
maxattachmentsize		= maximumattachmentsize
maxdirtybytes			= maxunsafebytesperscan
maxdirtymessages		= maxunsafemessagesperscan
maxgssize			= maxcustomspamscannersize
maxgstimeouts			= maxcustomspamscannertimeouts
maxmessagesize			= maximummessagesize
maxparts			= maximumattachmentspermessage
maxunscannedbytes		= maxunscannedbytesperscan
maxunscannedmessages		= maxunscannedmessagesperscan
maxzipdepth			= maximumarchivedepth
minattachmentsize		= minimumattachmentsize
minstars			= minimumstarsifonspamlist
mshmac				= WatermarkSecret
mshmacheader			= WatermarkHeader
mshmacnull			= TreatInvalidWatermarksWithNoSenderAsSpam
mshmacvalid			= WatermarkLifetime
namemodifysubject		= filenamemodifysubject
namesubjecttext			= filenamesubjecttext
newheadersattop			= placenewheadersattopofmessage
noisyviruses			= nonforgingviruses
normalrbls                      = spamliststobespam
nosenderprecedence		= nevernotifysendersofprecedence
noticefullheaders		= noticesincludefullheaders
noticerecipient			= noticesto
phishingblacklist		= phishingbadsitesfile
phishinghighlight		= highlightphishingfraud
phishingnumbers			= alsofindnumericphishing
phishingsubjecttag		= phishingsubjecttext
phishingwhitelist		= phishingsafesitesfile
outqueuedir			= outgoingqueuedir
procdbattempts			= maximumprocessingattempts
procdbname			= processingattemptsdatabase
quarantinesilent		= quarantinesilentviruses
quarantineuser			= quarantineuser
quarantinegroup			= quarantinegroup
quarantineperms			= quarantinepermissions
rbltimeoutlen			= spamlisttimeoutshistory
usesacache			= cachespamassassinresults
saactions			= spamassassinruleactions
sadecodebins			= IncludeBinaryAttachmentsInSpamAssassin
satimeoutlen			= spamassassintimeoutshistory
removeheaders			= removetheseheaders
replacetnef			= usetnefcontents
reqspamassassinscore		= requiredspamassassinscore
sacache				= spamassassincachedatabasefile
scanmail			= scanmessages
scoreformat			= spamscorenumberformat
secondlevellist                 = countrysubdomainslist
sendercontentreport		= senderbadcontentreport
senderfilenamereport		= senderbadfilenamereport
sendersizereport		= sendersizereport
showscanner			= includescannernameinreports
signalreadyscanned		= signmessagesalreadyprocessed
signunscannedmessages		= markunscannedmessages
sophosallowederrors		= allowedsophoserrormessages
spamblacklist			= isdefinitelyspam
spamdetail			= detailedspamreport
sizemodifysubject		= sizemodifysubject
sizesubjecttext			= sizesubjecttext
spamassassintempdir		= spamassassintemporarydir
spaminfected			= VirusNamesWhichAreSpam
spammodifysubject		= spammodifysubject
spamscorenotstars		= spamscorenumberinsteadofstars
spamstars			= spamscore
spamstarscharacter		= spamscorecharacter
spamstarsheader			= spamscoreheader
spamwhitelist			= isdefinitelynotspam
storedcontentmessage		= storedbadcontentmessagereport
storedfilenamemessage		= storedbadfilenamemessagereport
storedsizemessage		= storedsizemessagereport
storedvirusmessage		= storedvirusmessagereport
storeentireasdfqf		= quarantinewholemessagesasqueuefiles
strictphishing                  = usestricterphishingnet
stripdangeroustags		= convertdangeroushtmltotext
syntaxcheck			= automaticsyntaxcheck
unpackole			= UnpackMicrosoftDocuments
unscannedheader			= unscannedheadervalue
usedefaultswithmanyrecips       = usedefaultruleswithmultiplerecipients
tagphishingsubject		= phishingmodifysubject
virusmodifysubject		= virusmodifysubject
virusscan			= virusscanning
warnsenders			= notifysenders
warnvirussenders		= notifysendersofviruses
warnnamesenders			= notifysendersofblockedfilenamesorfiletypes
warnsizesenders                 = notifysendersofblockedsizeattachments
warnothersenders		= notifysendersofotherblockedcontent
# JKF 19/12/2007 warnpasswordsenders		= notifysendersofblockedpasswordprotectedarchives
webbugurl			= webbugreplacement
webbugblacklist			= knownwebbugservers
webbugwhitelist			= ignoredwebbugfilenames
whitelistmaxrecips		= ignorespamwhitelistifrecipientsexceed
workuser			= incomingworkuser
workgroup			= incomingworkgroup
workperms			= incomingworkpermissions


#
# Simple variables which can only have a single value, no rules allowed.
#

# These can be any of the words given, with the corresponding value stored.
# Format is	<Keyword Name>
#		<Default internal value>
#	      [ <External name> <Internal store value ] ...
#
[Simple,YesNo]
bayeswait		0	no	0	yes	1
clamavspam		0	no	0	yes	1
debug			0	no	0	yes	1
debugspamassassin	0	no	0	yes	1
deliverinbackground	1	no	0	yes	1
logdelivery		0	no	0	yes	1
lognonspam		0	no	0	yes	1
logsaactions		0	no	0	yes	1
logsilentviruses	0	no	0	yes	1
logspam			0	no	0	yes	1
logspeed		0	no	0	yes	1
expandtnef		1	no	0	yes	1
runinforeground		0	no	0	yes	1
showscanner		1	no	0	yes	1
spamassassinautowhitelist 1	no	0	yes	1
spliteximspool		0	no	0	yes	1
storeentireasdfqf	0	no	0	yes	1
syntaxcheck		1	no	0	yes	1
usedefaultswithmanyrecips	0	no	0	yes	1
SQLDebug		0	no	0	yes	1

# These should be checked for dir existence
[Simple,Dir]
incomingworkdir		/var/spool/baruwa/incoming
lockfiledir		/var/lock/Baruwa

# Check the first word of these for file existence
[Simple,File]
PhishingWhitelist	/var/lib/baruwa/phishingupdate/phishing.safe.sites.cdb
PhishingBlacklist	/var/lib/baruwa/phishingupdate/phishing.bad.sites.cdb
pidfile			/var/run/baruwa/scanner/Baruwa.pid
SecondLevelList         /etc/mail/baruwa/country.domains.conf
#spamassassinprefsfile	/etc/mail/baruwa/spam.assassin.prefs.conf
SpamListDefinitions	/etc/mail/baruwa/spam.lists.conf
VirusScannerDefinitions	/etc/mail/baruwa/virus.scanners.conf

# Check these to ensure they are just numbers
[Simple,Number]
AntiwordTimeout			50
BayesRebuild			0
Children			5
ClamdPort 3310
CriticalQueueSize		800
FileTimeout			20
fprotd6port			10200
GSTimeout			20
GSTimeoutLen			20
GunzipTimeout			50
MaxUnscannedBytes		100000000
MaxUnscannedMessages		30
MaxDirtyBytes			50000000
MaxDirtyMessages		30
MaxGSSize			20000
MaxGSTimeouts			10
MaxSpamAssassinTimeouts		10
ProcDBAttempts			6
QueueScanInterval		6
RBLTimeoutLen			10
RestartEvery			14400
SATimeoutLen			30
SpamListTimeout			10
SpamAssassinTimeout		75
VirusScannerTimeout		300
TNEFTimeout			120
UnrarTimeout			50
WhitelistMaxRecips		20
# For Qmail users
qmailhashdirectorynumber	23
qmailintdhashnumber		1

# These are all the other strings I haven't categorised.
# inqueuedir is here as it can be a glob (if it contains a * or a ?) or a
# filename containing a list of directories.
[Simple,Other]
cachetiming		1800,300,10800,172800,600
CustomFunctionsDir	/usr/share/Baruwa/CustomFunctions
FileCommand		/usr/bin/file
getipfromheader		0
GunzipCommand		/bin/gunzip
inqueuedir		/var/spool/exim.in/input
LDAPbase
LDAPserver
LDAPsite
LogFacility		mail
LogSock
BaruwaVersionNumber	1.0.0
MaxSpamAssassinSize		30000
MinimumCodeStatus	supported
MTA			exim
ProcDBName		/var/lib/baruwa/scanner/Processing.db
QuarantineUser
QuarantineGroup
QuarantinePerms		0600
RunAsUser		0
RunAsGroup		0
SACache			/var/lib/baruwa/scanner/SpamAssassin.cache.db
SophosAllowedErrors
spamassassintempdir	/var/spool/baruwa/SpamAssassin-Temp
SpamAssassinUserStateDir
SpamAssassinSiteRulesDir
SpamAssassinLocalRulesDir
SpamAssassinLocalStateDir
SpamAssassinDefaultRulesDir
SpamAssassinInstallPrefix
SpamInfected		Sane*UNOFFICIAL
SpamStarsCharacter	s
TNEFExpander		/usr/bin/tnef --maxsize=100000000
UnrarCommand		/usr/bin/unrar
VirusScanners		auto  # Space-separated list
WorkUser
WorkGroup
WorkPerms		0600
DBDSN
LocalDBDSN
DBUsername
DBPassword
SQLSerialNumber
SQLQuickPeek
SQLConfig
SQLRuleset
SQLSpamAssassinConfig
SphinxHost		127.0.0.1
SphinxPort		9306

#
# These variables match on any rule matching From:, else anything for To:
#

[First,YesNo]
AddTextOfDoc		0	no	0	yes	1
AllowExternal		0	no	0	yes	1
AllowPartial		0	no	0	yes	1
ArchivePublicKeys	0	no	0	yes	1
blacklistedishigh	0	no	0	yes	1
bouncespamasattachment	0	no	0	yes	1
CheckSAIfOnSpamList	1	no	0	yes	1
ContentModifySubject	start	no	0	yes	1	start	start	end	end
DeliverDisinfected	0	no	0	yes	1
DeliverSilent		0	no	0	yes	1
deliverunparsabletnef	0	no	0	yes	1
deliverymethod		batch	batch	batch	queue	queue
DisarmModifySubject	start	no	0	yes	1	start	start	end	end
EnableSpamBounce	0	no	0	yes	1
findarchivesbycontent	1	no	0	yes	1
gsscanner		0	no	0	yes	1
HideWorkDir		1	no	0	yes	1
HideWorkDirInNotice	0	no	0	yes	1
HighSpamModifySubject	start	no	0	yes	1	start	start	end	end
IncludeSpamHeader	0	no	0	yes	1
KeepSpamArchiveClean	0	no	0	yes	1
LastAfterBatch		0	no	0	yes	1
LastLookup		0	no	0	yes	1
ListSAScores		1	no	0	yes	1
#LoadSpamAssassin	0	no	0	yes	1
LogHTMLTags		0	no	0	yes	1
LogPermittedFilenames	0	no	0	yes	1
LogPermittedFiletypes	0	no	0	yes	1
LogPermittedFileMimetypes	0	no	0	yes	1
LookForUU		0	no	0	yes	1
MultipleHeaders		append	append	append	replace	replace	add	add
NameModifySubject	start	no	0	yes	1	start	start	end	end
NoticeFullHeaders	1	no	0	yes	1
RejectMessage		0	no	0	yes	1
ScannedModifySubject	0	no	0	yes	1	start	start	end	end
SendNotices		1	no	0	yes	1
SignAlreadyScanned	0	no	0	yes	1
SignCleanMessages	1	no	0	yes	1
SignUnscannedMessages	1	no	0	yes	1
SizeModifySubject	start	no	0	yes	1	start	start	end	end
SpamBlacklist		0	no	0	yes	1
SpamDetail		1	no	0	yes	1
SpamChecks		1	no	0	yes	1
SpamModifySubject	start	no	0	yes	1	start	start	end	end
SpamScoreNotStars	0	no	0	yes	1
SpamWhitelist		0	no	0	yes	1
StripDangerousTags	0	no	0	yes	1
UnpackOle		1	no	0	yes	1
UseSACache		1	no	0	yes	1
VirusModifySubject	start	no	0	yes	1	start	start	end	end
warningisattachment	1	no	0	yes	1
WarnSenders		1	no	0	yes	1
WarnVirusSenders	0	no	0	yes	1
WarnNameSenders		1	no	0	yes	1
WarnSizeSenders		0	no	0	yes	1
WarnOtherSenders	1	no	0	yes	1

[First,File]
DeletedContentMessage	/etc/mail/baruwa/reports/en/deleted.content.message.txt
DeletedFilenameMessage	/etc/mail/baruwa/reports/en/deleted.filename.message.txt
DeletedSizeMessage	/etc/mail/baruwa/reports/en/deleted.size.message.txt
DeletedVirusMessage	/etc/mail/baruwa/reports/en/deleted.virus.message.txt
DisinfectedReportText	/etc/mail/baruwa/reports/en/disinfected.report.txt
inlinehtmlsig		/etc/mail/baruwa/reports/en/inline.sig.html
inlinehtmlwarning	/etc/mail/baruwa/reports/en/inline.warning.html
inlinespamwarning	/etc/mail/baruwa/reports/en/inline.spam.warning.txt
inlinetextsig		/etc/mail/baruwa/reports/en/inline.sig.txt
inlinetextwarning	/etc/mail/baruwa/reports/en/inline.warning.txt
languagestrings
recipientspamreport	/etc/mail/baruwa/reports/en/recipient.spam.report.txt
rejectionreport		/etc/mail/baruwa/reports/en/message.rejection.report.txt
sendercontentreport 	/etc/mail/baruwa/reports/en/sender.content.report.txt
sendererrorreport 	/etc/mail/baruwa/reports/en/sender.error.report.txt
senderfilenamereport	/etc/mail/baruwa/reports/en/sender.filename.report.txt
SenderSizeReport	/etc/mail/baruwa/reports/en/sender.size.report.txt
sendervirusreport 	/etc/mail/baruwa/reports/en/sender.virus.report.txt
StoredContentMessage	/etc/mail/baruwa/reports/en/stored.content.message.txt
StoredFilenameMessage	/etc/mail/baruwa/reports/en/stored.filename.message.txt
StoredSizeMessage	/etc/mail/baruwa/reports/en/stored.size.message.txt
StoredVirusMessage	/etc/mail/baruwa/reports/en/stored.virus.message.txt

[First,Command]
Sendmail		/usr/sbin/exim

[First,Dir]
OutQueueDir			/var/spool/exim/input
PublicKeyArchiveDir		#/var/spool/baruwa/keys
quarantinedir			/var/spool/baruwa/quarantine

[First,Number]
HighRBLs			3
HighSpamAssassinScore		10
MaxAttachmentSize		-1
MaxMessageSize			0
MaxParts			200
MaxSpamCheckSize		150000
MaxSpamListTimeouts		7
MaxZipDepth			2
MinAttachmentSize		-1
MinStars			0
mshmacvalid			604800
NormalRBLs			1
ReqSpamAssassinScore		6

[First,Other]
Antiword			/usr/bin/antiword -f
ArchivesAre			zip rar ole
AttachmentCharset		UTF-8
attachimageinternalname
attachimagename
AttachmentWarningFilename	VirusWarning.txt
cleanheader			Found to be clean
ContentSubjectText		{Dangerous Content?}
DefaultRenamePattern		__FILENAME__.disarmed
dirtyheader			Found to be infected
DisarmSubjectText		{Disarmed}
DisinfectedHeader		Disinfected
EnvFromHeader			X-Baruwa-BaruwaFW-Envelope-From:
EnvToHeader			X-Baruwa-BaruwaFW-Envelope-To:
HighSpamSubjectText		{Spam?}
Hostname			the Baruwa
IDHeader			X-Baruwa-BaruwaFW-ID:
InfoHeader
InfoValue			Please contact the ISP for more information
IPVerHeader
LocalPostmaster			postmaster
MailHeader			X-Baruwa-BaruwaFW:
mshmac				Watermark-secret
mshmacheader			Baruwa-NULL-Check:
NameSubjectText			{Filename?}
NoticesFrom			Baruwa
NoticeSignature			-- \nBaruwa\nEmail Content Scanner\nwww.baruwa.com
PhishingSubjectTag		{Fraud?}
ScannedSubjectText		{Scanned}
ScoreFormat			%d
Sendmail2			/usr/sbin/exim -C /etc/exim/exim_out.conf
SpamHeader			X-Baruwa-BaruwaFW-SpamCheck:
SpamList
SpamVirusHeader			X-Baruwa-BaruwaFW-SpamVirus-Report:
SpamSubjectText			{Spam?}
SpamStarsHeader			X-Baruwa-BaruwaFW-SpamScore:
UnscannedHeader			Not Post-SMTP Content scanned
VirusSubjectText		{Virus?}
WebBugURL			http://datafeeds.baruwa.com/1x1spacer.gif
HamActions		deliver header "X-Spam-Status: No"
SpamActions		deliver header "X-Spam-Status: Yes"
HighScoreSpamActions	deliver header "X-Spam-Status: Yes"
SizeSubjectText		{Size}

[All,YesNo]
AddEnvFrom		1	no	0	yes	1
AddEnvTo		0	no	0	yes	1
addmshmac		1	no	0	yes	1
AllowIFrameTags		convert	no	0	yes	1	disarm	convert
AllowFormTags		convert	no	0	yes	1	disarm	convert
allowmultsigs		0	no	0	yes	1
AllowObjectTags		convert	no	0	yes	1	disarm	convert
AllowScriptTags		convert	no	0	yes	1	disarm	convert
AllowPassZips		0	no	0	yes	1
AllowWebBugTags		convert	no	0	yes	1	disarm	convert
assumeisdir		1	file	0	directory	1
attachimage		0	no	0	yes	1
attachimagetohtmlonly	1	no	0	yes	1
BlockEncrypted		0	no	0	yes	1
BlockUnencrypted	0	no	0	yes	1
checkppafilenames	1	no	0	yes	1
checkmshmac		1	no	0	yes	1
checkmshmacskip		1	no	0	yes	1
ClamdUseThreads		0	no	0	yes	1
DangerScan		1	no	0	yes	1
DeliverCleanedMessages	1	no	0	yes	1
FindPhishing		1	no	0	yes	1
markinfectedmessages	1	no	0	yes	1
PhishingHighlight	1	no	0	yes	1
HtmlToText		0	no	0	yes	1
InsistPassZips		0	no	0	yes	1
NewHeadersAtTop		0	no	0	yes	1
PhishingNumbers		1	no	0	yes	1
QuarantineInfections	1	no	0	yes	1
QuarantineModifiedBody	0	no	0	yes	1
QuarantineSilent	0	no	0	yes	1
QuarantineWholeMessage	0	no	0	yes	1
ReplaceTNEF		2	no	0	add	1	replace	2
sadecodebins		0	no	0	yes	1
ScanMail		1	no	0	yes	1	virus	2
SpamStars		1	no	0	yes	1
StrictPhishing          1       no      0       yes     1
TagPhishingSubject	0	no	0 	yes	1	start	start	end	end
UseSpamAssassin		1	no	0	yes	1
UseWatermarking		1	no	0	yes	1
VirusScan		1	no	0	yes	1

[All,File]
#FilenameRules		/etc/mail/baruwa/filename.rules.conf

[All,Other]
# This is the other stuff that came up in the search that I haven't
# figured out what to do with yet...
aallowfilenames
adenyfilemimetypes
adenyfiletypes
aallowfilemimetypes
aallowfiletypes
adenyfilenames
afilenamerules
afiletyperules
ArchiveMail
ClamdLockFile
ClamdSocket 127.0.0.1
FilenameRules
FiletypeRules
isareply
mshmacnull			spam
NoisyViruses			Joke/ OF97/ WM97/ W97M/ eicar
NoSenderPrecedence		list bulk
NoticeRecipient			postmaster
RemoveHeaders			X-Mozilla-Status: X-Mozilla-Status2:
SilentViruses			HTML-IFrame All-Viruses
SpamDomainList
webbugblacklist
webbugwhitelist
allowfilenames
denyfilemimetypes
denyfiletypes
allowfilemimetypes
allowfiletypes
denyfilenames
saactions
