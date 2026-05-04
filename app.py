from dotenv import load_dotenv
load_dotenv()
from flask import Flask, render_template, jsonify, request
import json
import random
from datetime import datetime
from groq import Groq

app = Flask(__name__)
import os
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

ATTAQUES = [
    {"rule_description": "Multiple authentication failures - Brute force detected", "rule_level": 10, "category": "Brute Force", "is_real_threat": True},
    {"rule_description": "SQL injection attempt detected on web application", "rule_level": 12, "category": "Web Attack", "is_real_threat": True},
    {"rule_description": "Port scan detected from external IP", "rule_level": 8, "category": "Reconnaissance", "is_real_threat": True},
    {"rule_description": "Rootkit detection - suspicious file modified", "rule_level": 14, "category": "Malware", "is_real_threat": True},
    {"rule_description": "XSS attack attempt on web application", "rule_level": 11, "category": "Web Attack", "is_real_threat": True},
    {"rule_description": "Unauthorized privilege escalation attempt", "rule_level": 13, "category": "Privilege Escalation", "is_real_threat": True},
    {"rule_description": "SSH login success from known user", "rule_level": 3, "category": "Normal Activity", "is_real_threat": False},
    {"rule_description": "Windows update service started", "rule_level": 2, "category": "Normal Activity", "is_real_threat": False},
    {"rule_description": "Antivirus scan completed successfully", "rule_level": 1, "category": "Normal Activity", "is_real_threat": False},
]

AGENTS = ["server-prod-01", "server-prod-02", "dc-01", "web-server-01", "workstation-15", "firewall-01"]

def charger_alertes():
    try:
        with open("data/alertes_enrichies.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return []

def sauvegarder_alertes(alertes):
    with open("data/alertes_enrichies.json", "w", encoding="utf-8") as f:
        json.dump(alertes, f, indent=2, ensure_ascii=False)

def analyser_avec_ia(alerte):
    prompt = f"""
Tu es un expert en cybersécurité SOC.
Analyse cette alerte Wazuh et réponds UNIQUEMENT en JSON valide avec exactement ces 4 champs :
- "criticite" : Low / Medium / High / Critical
- "est_faux_positif" : true ou false
- "explication" : 2 phrases en français expliquant la menace
- "recommandation" : action concrète à faire en français

Alerte :
- Description : {alerte['rule']['description']}
- Niveau Wazuh : {alerte['rule']['level']}/15
- Catégorie : {alerte['rule']['category']}
- Agent : {alerte['agent']['name']}
- IP source : {alerte['data']['srcip']}

Réponds UNIQUEMENT avec le JSON, sans texte avant ou après.
"""
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": "Tu es un expert SOC. Tu réponds uniquement en JSON valide, sans markdown."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.1
    )
    texte = response.choices[0].message.content.strip()
    if texte.startswith("```"):
        texte = texte.split("```")[1]
        if texte.startswith("json"):
            texte = texte[4:]
    return json.loads(texte.strip())

@app.route("/")
def dashboard():
    return render_template("dashboard.html")

@app.route("/api/stats")
def stats():
    alertes = charger_alertes()
    analysees = [a for a in alertes if a.get("analyse_ia")]
    total = len(analysees)
    vrais_positifs = sum(1 for a in analysees if not a["analyse_ia"]["est_faux_positif"])
    faux_positifs = sum(1 for a in analysees if a["analyse_ia"]["est_faux_positif"])
    correctes = sum(1 for a in analysees if a.get("detection_correcte"))
    criticites = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for a in analysees:
        c = a["analyse_ia"].get("criticite", "Low")
        if c in criticites:
            criticites[c] += 1
    categories = {}
    for a in analysees:
        cat = a["rule"]["category"]
        categories[cat] = categories.get(cat, 0) + 1

    # Timeline — alertes par heure
    timeline = {}
    for a in analysees:
        heure = a["timestamp"][:13]
        timeline[heure] = timeline.get(heure, 0) + 1

    return jsonify({
        "total": total,
        "vrais_positifs": vrais_positifs,
        "faux_positifs": faux_positifs,
        "taux_precision": round((correctes / total) * 100, 1) if total > 0 else 0,
        "criticites": criticites,
        "categories": categories,
        "timeline": timeline
    })

@app.route("/api/alertes")
def alertes():
    search = request.args.get("search", "").lower()
    filtre = request.args.get("filtre", "all")
    data = charger_alertes()
    analysees = [a for a in data if a.get("analyse_ia")]
    result = []
    for a in analysees:
        item = {
            "id": a["id"],
            "timestamp": a["timestamp"],
            "description": a["rule"]["description"],
            "level": a["rule"]["level"],
            "category": a["rule"]["category"],
            "agent": a["agent"]["name"],
            "srcip": a["data"]["srcip"],
            "criticite": a["analyse_ia"]["criticite"],
            "est_faux_positif": a["analyse_ia"]["est_faux_positif"],
            "explication": a["analyse_ia"]["explication"],
            "recommandation": a["analyse_ia"]["recommandation"],
            "detection_correcte": a.get("detection_correcte", False)
        }
        result.append(item)
    ordre = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    result.sort(key=lambda x: ordre.get(x["criticite"], 4))

    # Filtres
    if filtre == "fp":
        result = [a for a in result if a["est_faux_positif"]]
    elif filtre in ["Critical", "High", "Medium", "Low"]:
        result = [a for a in result if a["criticite"] == filtre]
    if search:
        result = [a for a in result if search in a["description"].lower() or search in a["agent"].lower()]
    return jsonify(result)

@app.route("/api/simuler", methods=["POST"])
def simuler_attaque():
    template = random.choice(ATTAQUES)
    alertes = charger_alertes()
    
    nouvel_id = f"ALT-SIM-{len(alertes)+1:04d}"
    nouvelle_alerte = {
        "id": nouvel_id,
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "rule": {
            "description": template["rule_description"],
            "level": template["rule_level"],
            "groups": ["simulated"],
            "category": template["category"]
        },
        "agent": {
            "name": random.choice(AGENTS),
            "ip": f"192.168.{random.randint(1,5)}.{random.randint(1,254)}"
        },
        "data": {
            "srcip": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "protocol": random.choice(["TCP", "UDP", "HTTP", "SSH"])
        },
        "is_real_threat": template["is_real_threat"]
    }

    try:
        analyse = analyser_avec_ia(nouvelle_alerte)
        nouvelle_alerte["analyse_ia"] = {
            "criticite": analyse.get("criticite", "Medium"),
            "est_faux_positif": analyse.get("est_faux_positif", False),
            "explication": analyse.get("explication", ""),
            "recommandation": analyse.get("recommandation", "")
        }
        ia_dit_faux = analyse.get("est_faux_positif", False)
        reel_faux = not template["is_real_threat"]
        nouvelle_alerte["detection_correcte"] = ia_dit_faux == reel_faux
    except Exception as e:
        nouvelle_alerte["analyse_ia"] = None
        nouvelle_alerte["detection_correcte"] = False

    alertes.append(nouvelle_alerte)
    sauvegarder_alertes(alertes)
    return jsonify({"success": True, "alerte": nouvelle_alerte})

if __name__ == "__main__":
    app.run(debug=True)