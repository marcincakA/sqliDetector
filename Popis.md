V prvom kroku tokenizer vytvory tokeny
V druhom kroku prechadza analyzer tokeny (init) a vytvori si hashmapu [cislo.riadku][riadok] (riadok je pole tokenov)
    //nepotrebne znaky preskakuje (whitespace, komentare)

    //taktiez vytvori hasmapu pouzitych premennych [nazov_premennej][cislo_riadku]
    //vytvori pole execution points [] ktore uchovava cisla riadkov s vyskytom exec pointu (mysqli_query,mysqli_real_query)

3. Krok (analyze exec points) //
    //hlada sql prikaz
    //prechadza premenne pouzite v exec pointe
        //ak najde v premennej sql prikaz, kontroluje ostatne premenne ktore boli pouzite na jeho vytvorenie
            //kontroluje ci premenne pouzite na vytvorenie prikazu maju pred konstrukciou prikazu pouzitu metodu 'mysqli_real_escape_string';
            Ak nie tato premenna je zranitelna

riešenie je dostupné na adrese: https://github.com/marcincakA/sqliDetector