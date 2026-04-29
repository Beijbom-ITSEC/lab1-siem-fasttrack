I den här labben har jag sätt upp en agent för att skicka loggar till en SIEM. Central logghantering är standard i varje SOC så att skapa en förståelse för hur en agent agerar, vilka regler som finns, hur man skriver regler och hur man kan automatisera response är kritiskt att kunna på en arbetsplats.


[Active Agent](screenshots/Activagent.png)

Regel Beskrivning

Regel 100001 upptäcker upprepade försök från samma IP:address. T1110 är ID för en bruteforce attack i MITTRE ATT&CK. Regeln larmar ifall samma oå address har försökt kolla upp sig mer än 5 gånger inom 12 sekunder. Det blir ett lagom tempo så man inte får med folk som bara råkar skriva fel lösenord. Om man höjer tröskeln för högt så spelar inte regeln någon roll ifall angriparen kommer in på 9 försök.
Regel 100002 kollar ifall man har lyckats logga in efter flera misslyckade försök. Det kan vara tecken på att man lagt sig under radarn med antalet försök och sedan tillslut lyckats knäcka ett lösenord. Den har också ID T1110 eftersom det fortfarande handlar om en bruteforce attack. Det är fortfarande bara ifall det kommer ifrån samma IP:addres så ifall man testar ifrån olika maskiner märker inte den här regeln det. 
Regel 100010 kollar ifall en ny fil i /etc/cron.d/ skapas. Det är inget en vanlig använder bör göra därav larm. Cron används för att göra handlingar vid vissa tider så är ett täcken på att någon försöker orsaka skada. T1053.003 MITRE ID står för Cron baserad attack, med inriktning på att man t.ex lägger en händelse vid start av maskinen.


