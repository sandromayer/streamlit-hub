import os
import requests
from jose import jwt
import streamlit as st
from functools import wraps

class KeycloakAuth:
    def __init__(self):
        self.client_id = os.getenv('KEYCLOAK_CLIENT_ID')
        self.client_secret = os.getenv('KEYCLOAK_CLIENT_SECRET')
        self.realm = os.getenv('KEYCLOAK_REALM')
        self.authority = os.getenv('KEYCLOAK_URL')
        self.redirect_uri = os.getenv("KEYCLOAK_REDIRECT_URI")
        self.scope = "openid"

    def authenticate_user(self, auth_code):
        """ Holt den Access-Token von Keycloak mithilfe des Autorisierungscodes """
        token_endpoint = f"{self.authority}/protocol/openid-connect/token"
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        response = requests.post(token_endpoint, data=token_data)

        if response.status_code != 200:
            st.error(f"Fehler bei der Authentifizierung: {response.text}")
            return None

        return response.json()

    def check_role(self, id_token, required_role="test_role"):
        """ Überprüft, ob der Benutzer die erforderliche Rolle hat """
        claims = jwt.get_unverified_claims(id_token)
        roles = claims.get("resource_access", {}).get("streamlit", {}).get("roles", [])
        return required_role in roles

    def oidc_login(self):
        """ Erstellt die OIDC-Login-URL und leitet den Benutzer zur Keycloak-Login-Seite weiter """
        auth_url = (
            f"{self.authority}/protocol/openid-connect/auth"
            f"?client_id={self.client_id}"
            f"&response_type=code"
            f"&scope={self.scope}"
            f"&redirect_uri={self.redirect_uri}"
        )
        st.markdown(f"[Login with OIDC]({auth_url})")
        st.stop()

    def require_role(self, required_role):
        """ Ein Decorator, der überprüft, ob der Benutzer die erforderliche Rolle hat """

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if "token" not in st.session_state:
                    st.error("Sie sind nicht eingeloggt.")
                    auth_code = st.experimental_get_query_params().get("code")
                    if not auth_code:
                        self.oidc_login()
                    token_data = self.authenticate_user(auth_code[0])
                    st.session_state["token"] = token_data["access_token"]

                id_token = st.session_state["token"]
                if not self.check_role(id_token, required_role):
                    st.error(f"Zugriff verweigert: Sie haben nicht die erforderliche Rolle '{required_role}'.")
                    return None
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def require_any_role(self, roles):
        """
        Ein Decorator, der überprüft, ob der Benutzer mindestens eine der angegebenen Rollen hat (ODER-Logik).
        """

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                if "token" not in st.session_state:
                    st.error("Sie sind nicht eingeloggt.")
                    auth_code = st.experimental_get_query_params().get("code")
                    if not auth_code:
                        self.oidc_login()
                    token_data = self.authenticate_user(auth_code[0])
                    st.session_state["token"] = token_data["access_token"]

                id_token = st.session_state["token"]

                # Mindestens eine der Rollen muss erfüllt sein (ODER-Logik)
                if not any(self.check_role(id_token, role) for role in roles):
                    st.error(
                        f"Zugriff verweigert: Sie benötigen mindestens eine der folgenden Rollen: {', '.join(roles)}.")
                    return None
                return func(*args, **kwargs)

            return wrapper

        return decorator

