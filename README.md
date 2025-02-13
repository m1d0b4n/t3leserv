
# Installation
0️⃣
```
git clone https://github.com/m1d0b4n/t3leserv.git && cd t3leserv
```
1️⃣

<<<<<<< HEAD
Edit the .env file with your correct data.
=======
- `TELEGRAM_BOT_TOKEN` : Votre token pour l'API de telegram généré par @BotFather

- `PROXY_URL` : Si le serveur est deployé dérrière un proxy, l'URL finale doit être paramètré avec ce variable

- `CHAT_ID` : L'ID du chat à envoyer le rapport

- `PORT` : Le port de démarrage du serveur Express

- `REDIRECT_URL` : L'URL de redirection pour le ressource  `/track`
>>>>>>> 60c388d (Ajout commande /report au bot telegram)

2️⃣
```
npm install
```
3️⃣
```
npm start
```
4️⃣

use ```ngrok``` for public expose
