# CallShield Spam Database

Pipeline de collecte, structuration et generation de base anti-spam pour CallShield.

## Structure

- data/raw-source-database.json : donnees brutes
- data/scored-database.json : donnees intermediaires / scorees
- data/device-database.json : base optimisee pour l'app iOS
- scraper/callshield_scraper.py : collecte
- scripts/build_spam_database.py : generation base finale
- output/spam-database.json : sortie generee

## Objectif

1. Construire une base spam fiable
2. Appliquer un scoring
3. Selectionner les meilleurs numeros pour CallKit
4. Alimenter l'app iOS CallShield
