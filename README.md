# Système IA d'Analyse des Alertes de Cybersécurité Wazuh

Projet de Fin d'Études  MIAGE L3  2025/2026  



##  Description

Système d'intelligence artificielle permettant d'analyser et classifier 
automatiquement les alertes de sécurité détectées par le SIEM Wazuh, 
afin de réduire les faux positifs et prioriser les vraies menaces.

##  Architecture

Alertes Wazuh (JSON) → Pipeline Python → LLM (Groq/Llama) → Dashboard Flask

##  Fonctionnalités

- ✅ Analyse automatique des alertes par IA (LLM Llama 3.3)
- ✅ Classification : Low / Medium / High / Critical
- ✅ Détection des faux positifs
- ✅ Recommandations d'actions correctives en français
- ✅ Dashboard temps réel avec graphiques
- ✅ Simulation d'attaques en live
- ✅ Précision de détection

