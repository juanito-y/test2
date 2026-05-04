from dotenv import load_dotenv
load_dotenv()
import json
import time
from groq import Groq
import os

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

def analyser_alerte(alerte):
    prompt = f"""
Tu es un expert en cybersécurité SOC.
Analyse cette alerte Wazuh et réponds UNIQUEMENT en JSON valide avec exactement ces 4 champs :
- "criticite" : Low / Medium / High / Critical
- "est_faux_positif" : true ou false
- "explication" : 2 phrases en français expliquant la menace
- "recommandation" : action concrète à faire en français

Alerte :
- ID : {alerte['id']}
- Description : {alerte['rule']['description']}
- Niveau Wazuh : {alerte['rule']['level']}/15
- Catégorie : {alerte['rule']['category']}
- Groupes : {alerte['rule']['groups']}
- Agent source : {alerte['agent']['name']}
- IP agent : {alerte['agent']['ip']}
- IP source : {alerte['data']['srcip']}
- Protocole : {alerte['data']['protocol']}
- Timestamp : {alerte['timestamp']}

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {
                "role": "system",
                "content": "Tu es un expert SOC en cybersécurité. Tu réponds uniquement en JSON valide, sans markdown, sans backticks."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.1
    )

    return response.choices[0].message.content

def nettoyer_json(texte):
    # Enlève les backticks si le modèle en met quand même
    texte = texte.strip()
    if texte.startswith("```"):
        texte = texte.split("```")[1]
        if texte.startswith("json"):
            texte = texte[4:]
    return texte.strip()

# Charge les alertes
with open("data/alertes_wazuh.json", "r", encoding="utf-8") as f:
    alertes = json.load(f)

print(f"🔍 Analyse de {len(alertes)} alertes en cours...\n")

resultats = []
correct = 0

for i, alerte in enumerate(alertes):
    print(f"[{i+1}/{len(alertes)}] Analyse de {alerte['id']} — {alerte['rule']['description'][:50]}...")

    try:
        reponse_brute = analyser_alerte(alerte)
        reponse_propre = nettoyer_json(reponse_brute)
        analyse = json.loads(reponse_propre)

        # Vérifie si l'IA a bien détecté (faux positif ou vraie menace)
        ia_dit_faux = analyse.get("est_faux_positif", False)
        reel_faux = not alerte["is_real_threat"]
        
        if ia_dit_faux == reel_faux:
            correct += 1
            statut = "✅"
        else:
            statut = "❌"

        # Ajoute les résultats enrichis
        alerte_enrichie = {
            **alerte,
            "analyse_ia": {
                "criticite": analyse.get("criticite", "Unknown"),
                "est_faux_positif": analyse.get("est_faux_positif", False),
                "explication": analyse.get("explication", ""),
                "recommandation": analyse.get("recommandation", "")
            },
            "detection_correcte": ia_dit_faux == reel_faux
        }

        resultats.append(alerte_enrichie)
        print(f"   {statut} Criticité: {analyse.get('criticite')} | Faux positif: {analyse.get('est_faux_positif')}")

    except Exception as e:
        print(f"   ⚠️ Erreur sur {alerte['id']}: {e}")
        resultats.append({**alerte, "analyse_ia": None, "detection_correcte": False})

    # Pause pour éviter le rate limiting Groq
    time.sleep(2)

# Sauvegarde les résultats enrichis
with open("data/alertes_enrichies.json", "w", encoding="utf-8") as f:
    json.dump(resultats, f, indent=2, ensure_ascii=False)

# Affiche les stats finales
taux = (correct / len(alertes)) * 100
print(f"\n{'='*50}")
print(f" Analyse terminée !")
print(f" Alertes analysées : {len(alertes)}")
print(f" Taux de détection correct : {correct}/{len(alertes)} ({taux:.1f}%)")
print(f" Résultats sauvegardés dans data/alertes_enrichies.json")