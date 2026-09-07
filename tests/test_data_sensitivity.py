from cyberwatch import data_sensitivity


def detail(*values, summary=""):
    return {
        "data_types": [{"value": value, "status": "claimed"} for value in values],
        "display_summary": summary,
        "claims": [],
        "fields": {},
    }


def test_identite_adresse_telephone_sont_des_donnees_personnelles():
    result = data_sensitivity.classify(detail(
        "noms et prénoms", "adresses postales", "numéros de téléphone"
    ))
    assert result["personal_data_exposed"] is True
    assert result["high_sensitivity_data_exposed"] is False
    assert result["credentials_or_secrets_exposed"] is False


def test_mots_de_passe_pluriel_sont_des_secrets_et_restent_sensibles():
    result = data_sensitivity.classify(detail("mots de passe"))
    assert result["credentials_or_secrets_exposed"] is True
    assert result["sensitive_data_exposed"] is True
    assert result["sensitive_data_types"] == ["mots de passe"]


def test_iban_et_sante_sont_de_haute_sensibilite():
    result = data_sensitivity.classify(detail("IBAN / RIB", "données de santé"))
    assert result["high_sensitivity_data_exposed"] is True
    assert result["sensitive_data_exposed"] is True


def test_mineurs_declenchent_le_niveau_vulnerable_et_haute_sensibilite():
    result = data_sensitivity.classify(detail(
        "dates de naissance", summary="Données d’adhérents, dont des mineurs, diffusées."
    ))
    assert result["vulnerable_people_data_exposed"] is True
    assert result["high_sensitivity_data_exposed"] is True


def test_consistency_alerts_detect_corrupted_legacy_flag():
    alerts = data_sensitivity.consistency_alerts({
        "personal_data_exposed": True,
        "high_sensitivity_data_exposed": False,
        "credentials_or_secrets_exposed": True,
        "sensitive_data_exposed": False,
    })
    assert [alert["code"] for alert in alerts] == ["SENSITIVE_FLAG_INCONSISTENT"]
