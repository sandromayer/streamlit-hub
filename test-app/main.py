import streamlit as st
from jose import jwt
import requests
import os

# Konfigurationswerte aus Umgebungsvariablen holen
CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")
CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
AUTHORITY = os.getenv("KEYCLOAK_AUTHORITY")
REDIRECT_URI = os.getenv("KEYCLOAK_REDIRECT_URI")
SCOPE = os.getenv("KEYCLOAK_SCOPE", "openid")

# Funktion zur Authentifizierung und Abruf des Tokens
def authenticate_user(auth_code):
    token_endpoint = f"{AUTHORITY}/protocol/openid-connect/token"
    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    response = requests.post(token_endpoint, data=token_data)
    # Debug-Ausgaben, um den Fehler zu identifizieren
    st.write(f"Status Code: {response.status_code}")
    st.write(f"Response Text: {response.text}")

    response.raise_for_status()  # Hebt die HTTPError bei Fehlern an

    return response.json()


# Überprüfen der Rolle im ID Token
def check_role(id_token):
    claims = jwt.get_unverified_claims(id_token)
    roles = claims.get("resource_access", {}).get("streamlit", {}).get("roles", [])
    return "test_role" in roles  # Ersetze "required_role" mit der tatsächlich benötigten Rolle

# OIDC-Login-Seite
def oidc_login():
    auth_url = (
        f"{AUTHORITY}/protocol/openid-connect/auth"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&scope={SCOPE}"
        f"&redirect_uri={REDIRECT_URI}"
    )
    st.markdown(f"[Login with OIDC]({auth_url})")


# Hauptlogik der App
def main():
    st.title("OIDC Authentifizierte Streamlit App")

    # Überprüfen, ob der Auth-Code als Query-Parameter vorhanden ist
    query_params = st.experimental_get_query_params()
    if "code" not in query_params:
        st.write("Bitte melden Sie sich an, um fortzufahren:")
        oidc_login()
    else:
        auth_code = query_params["code"][0]
        token_data = authenticate_user(auth_code)
        id_token = token_data["access_token"]

        if check_role(id_token):
            st.success("Erfolgreich authentifiziert!")
            st.write("Token Inhalt:")
            st.json(jwt.get_unverified_claims(id_token))
        else:
            st.error("Zugriff verweigert: Sie haben nicht die erforderliche Rolle.")

if __name__ == "__main__":
    main()
