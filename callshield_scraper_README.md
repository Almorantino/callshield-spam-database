# CallShield scraper

Ce scraper construit `spam-database.json` à partir de :
- la liste officielle ARCEP des préfixes de démarchage
- une liste de sources publiques **que tu as validées** dans `callshield_sources.example.json`

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests beautifulsoup4
```

## Générer le JSON

```bash
python callshield_scraper.py --sources callshield_sources.example.json --output spam-database.json
```

## Push GitHub automatique

```bash
export GITHUB_TOKEN=ton_token_github
python callshield_scraper.py \
  --sources callshield_sources.example.json \
  --output spam-database.json \
  --push-github \
  --github-repo Almorantino/callshield-spam-database
```

## Important

- N'ajoute dans le manifest que des sources **publiques** que tu as vérifiées.
- Évite de scraper des sites si leurs conditions l'interdisent.
- La page ARCEP fournit les préfixes officiels de démarchage, pas une base exhaustive de numéros.
