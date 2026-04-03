# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Django web application for **Quantitative Network Security** — scans networks for vulnerabilities, uses ML (scikit-learn RandomForest) to recommend defense techniques, and generates security reports. Built with Django 5.0, MySQL, Bootstrap 4, and crispy-forms.
x
## Common Commands

```bash
# Setup (virtualenv is qnetvenv/)
python -m venv qnetvenv
source qnetvenv/bin/activate  # macOS/Linux
pip install -r requirements.txt

# Database (MySQL required — configure credentials in settings.py)
python manage.py makemigrations
python manage.py migrate
python manage.py loaddata initial_data.json
python manage.py populate_defense_data

# Run server
python manage.py runserver

# ML model training
python manage.py train_ml_model

# Check ML model status
python check_ml_status.py
```

## Architecture

**Django apps and their responsibilities:**

- **accounts** — User auth, registration, profiles (`UserProfile` with role-based access: user/admin), activity logging
- **dashboard** — Main dashboard views after login
- **vulnerability** — Core domain: `NetworkEnvironment` → `VulnerabilityScan` → `Vulnerability` → `VulnerabilityCountermeasure`. Handles network scanning and vulnerability tracking with CVSS scores
- **defense** — ML-powered defense recommendations. `DefenseTechnique` → `DefenseRecommendation` → `DefenseImplementation`. Contains the ML pipeline (`ml_recommender.py`, `ml_model_trainer_real.py`)
- **reports** — Generates security assessment reports (PDF/JSON) from scan and defense data
- **admin_panel** — Custom admin dashboard for user management, system analytics, network config

**ML Pipeline:**
- `defense/ml_recommender.py` — `DefenseRecommender` class using RandomForest to predict defense techniques from vulnerability attributes (type, severity, CVSS, exploit availability)
- `defense/ml_model_trainer_real.py` — Production trainer using real DB data
- Trained models saved to `ml_models/trained_models/`
- Training data in `datasets/training_dataset.json`
- Management command: `train_ml_model`

**Key design patterns:**
- Root URL (`/`) redirects to login; all app routes require authentication
- `UserProfile` auto-created via Django signals on User creation
- Templates use Bootstrap 4 via crispy-forms; app templates in `<app>/templates/<app>/`, shared templates in `templates/`
- Database is MySQL (`Quantitative_netwotk_db`); credentials in `settings.py` (need to be configured per environment)

## Database

MySQL backend. All models use explicit `db_table` names (e.g., `vulnerability_scan`, `defense_technique`). The DB name is `Quantitative_netwotk_db`.
