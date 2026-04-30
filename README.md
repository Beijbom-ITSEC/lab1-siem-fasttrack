I den här labben har jag sätt upp en agent för att skicka loggar till en SIEM. Central logghantering är standard i varje SOC så att skapa en förståelse för hur en agent agerar, vilka regler som finns, hur man skriver regler och hur man kan automatisera response är kritiskt att kunna på en arbetsplats.

**Active Agent**
<img width="900" height="43" alt="Activagent" src="https://github.com/user-attachments/assets/f21add89-4bcc-4b5b-aa3e-a5478210a715" />

**Fungerande FIM **
<img width="1136" height="299" alt="FIMfungerande" src="https://github.com/user-attachments/assets/8af82dd3-bd00-4bb7-bb23-9f004b371842" />


**Regel Beskrivning**

**Regel 100001** upptäcker upprepade försök från samma IP:address. T1110 är ID för en bruteforce attack i MITTRE ATT&CK. Regeln larmar ifall samma oå address har försökt kolla upp sig mer än 5 gånger inom 12 sekunder. Det blir ett lagom tempo så man inte får med folk som bara råkar skriva fel lösenord. Om man höjer tröskeln för högt så spelar inte regeln någon roll ifall angriparen kommer in på 9 försök.
**Regel 100002** kollar ifall man har lyckats logga in efter flera misslyckade försök. Det kan vara tecken på att man lagt sig under radarn med antalet försök och sedan tillslut lyckats knäcka ett lösenord. Den har också ID T1110 eftersom det fortfarande handlar om en bruteforce attack. Det är fortfarande bara ifall det kommer ifrån samma IP:addres så ifall man testar ifrån olika maskiner märker inte den här regeln det. 
**Regel 100010** kollar ifall en ny fil i /etc/cron.d/ skapas. Det är inget en vanlig använder bör göra därav larm. Cron används för att göra handlingar vid vissa tider så är ett täcken på att någon försöker orsaka skada. T1053.003 MITRE ID står för Cron baserad attack, med inriktning på att man t.ex lägger en händelse vid start av maskinen.

Output och analys från anomalidetektorn — vad hittade modellen?
<img width="885" height="619" alt="image" src="https://github.com/user-attachments/assets/fcc0ed71-3b72-4728-9883-4d46abd07139" />

Det var två stora event som hände räknades som anomalis om jag tolkar anomaly_results korrekt. En 26 april mellan 02:00 till 04:00 och en 27 april mellan 14:00 och 16:00. Majoriteten av larmen räknades inte som anomalys i datan men det finns några få events som ses som True anomali events.




**Reflektion:** Vad skulle jag övervaka på ett riktigt system?
Jag tycker att det finns en bra grund med basregler i wazuh som jag skulle modifiera först och sedan lagt till regler vid behov. Att ha reglerna som en process och inte en färdig handling. Därför har jag svårt att placera
exakt vad jag hade övervakat eftersom det beror på vart man hamnar och vilka resurser som finns där. En grej jag tror jag hade gjort är att göra en stark FIM lista så man har kolla på viktiga filer anvädnaren inte har 
mycket anledning att ändra i men en attackerare har. Jag tänker även loggar över vilka program som t.ex en pdf läsare försöker öppna eftersom med min grundläggande kunskap så är phising mycket ett allvarlig hot och 
som jag förstått det används sånna program för att ta sig vidare in på en enhet. Så man har får ett larm ifall et pdf program vill försöka få datorn att öppna en skum hemsida som exempel.

Eftersom jag inte heller jobbat med SIEM regler särkilt länge så har jag svårt att avgöra hur komplicerade man kan få reglerna att vara men då tänker jag också att man behöver skriva väldigt långa och unika regler som man sedan behöver dokumentera.
Vilka regler som finns, hur dom är skrivna och hur det vardagliga arbete över att skjustera reglerna är något jag ska vara noga med att lära mig på min LIA framöver.

**Nätverks karta**
<img width="940" height="442" alt="image" src="https://github.com/user-attachments/assets/51d1c678-52b0-4d01-ae2c-0b953edae2d3" />

**Min Egna Dashboard**
<img width="1910" height="914" alt="dashboard" src="https://github.com/user-attachments/assets/dd5695f3-b3de-4b10-a437-b6f22d8b026e" />
