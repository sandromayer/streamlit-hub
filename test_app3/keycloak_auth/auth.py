import os
import requests
from jose import jwt
import streamlit as st
from functools import wraps
from datetime import datetime, timezone
from streamlit_cookies_controller import CookieController

controller = CookieController()

class KeycloakAuth:
    def __init__(self):
        self.client_id = os.getenv('KEYCLOAK_CLIENT_ID', "streamlit")
        self.client_secret = os.getenv('KEYCLOAK_CLIENT_SECRET')
        self.realm = os.getenv('KEYCLOAK_REALM')
        self.authority = os.getenv('KEYCLOAK_AUTHORITY')
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
            st.error(f"Fehler bei der Authentifizierung: {response.json()}")
            return None

        return response.json()

    def refresh_access_token(self):
        """Verwende den Refresh Token, um einen neuen Access Token zu erhalten."""
        if "token" not in st.session_state or "refresh_token" not in st.session_state["token"]:
            raise Exception("Kein Refresh Token vorhanden.")

        refresh_token = st.session_state["token"].get("refresh_token")

        token_endpoint = f"{self.authority}/protocol/openid-connect/token"
        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        response = requests.post(token_endpoint, data=token_data)
        if response.status_code != 200:
            st.error("Fehler beim Aktualisieren des Tokens. Bitte erneut einloggen.")
            st.session_state.clear()  # Lösche die Session-Daten
            self.oidc_login()

        new_token_data = response.json()

        # Speichere den aktualisierten Access Token und Refresh Token im Session State und im Cookie
        st.session_state["token"]["access_token"] = new_token_data["access_token"]
        st.session_state["token"]["refresh_token"] = new_token_data.get("refresh_token", refresh_token)

        # Tokens in einem Cookie speichern
        self.save_tokens_to_cookies(new_token_data["access_token"], new_token_data.get("refresh_token", refresh_token))

    def save_tokens_to_cookies(self, access_token, refresh_token):
        """Speichert die Tokens in einem Cookie"""
        controller.set("access_token", access_token)
        controller.set("refresh_token", refresh_token)

    def load_tokens_from_cookies(self):
        """Lädt die Tokens aus dem Cookie und speichert sie im Session State"""
        access_token = controller.get("access_token")
        refresh_token = controller.get("refresh_token")
        if access_token and refresh_token:
            st.session_state["token"] = {
                "access_token": access_token,
                "refresh_token": refresh_token
            }

    def require_role(self, required_roles, logic="OR"):
        """
        Ein Decorator, der überprüft, ob der Benutzer die angegebenen Rollen hat.
        - Wenn `logic="AND"`, müssen alle Rollen erfüllt sein.
        - Wenn `logic="OR"`, muss mindestens eine Rolle erfüllt sein.
        """

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Initialisiere den session_state, falls er nicht existiert
                if "token" not in st.session_state:
                    st.session_state["token"] = {}
                    # Lade Tokens aus dem Cookie in den Session State
                    self.load_tokens_from_cookies()

                # Prüfen, ob der Benutzer bereits eingeloggt ist und ein Access Token existiert
                if "access_token" not in st.session_state["token"]:
                    # Falls kein Access Token vorhanden ist, versuche, den Benutzer zu authentifizieren
                    self.check_authentication()

                # Access Token aus Session State extrahieren
                access_token = st.session_state["token"].get("access_token")

                if access_token is None:
                    st.error("Keine gültige Authentifizierung gefunden.")
                    return None

                # Überprüfen, ob der Access Token abgelaufen ist
                if self.is_token_expired(access_token):
                    # Versuche, den Access Token mit dem Refresh Token zu aktualisieren
                    try:
                        self.refresh_access_token()
                        access_token = st.session_state["token"]["access_token"]
                    except Exception as e:
                        st.error(f"Fehler beim Aktualisieren des Tokens: {str(e)}")
                        return None

                # Rollenprüfung mit AND- oder OR-Logik
                if logic == "AND":
                    if not all(self.check_role(access_token, role) for role in required_roles):
                        st.error(
                            f"Zugriff verweigert: Sie benötigen **alle** der folgenden Rollen: {', '.join(required_roles)}.")
                        return None
                elif logic == "OR":
                    if not any(self.check_role(access_token, role) for role in required_roles):
                        st.error(
                            f"Zugriff verweigert: Sie benötigen **mindestens eine** der folgenden Rollen: {', '.join(required_roles)}.")
                        return None
                return func(*args, **kwargs)

            return wrapper

        return decorator

    def check_authentication(self):
        """
        Überprüft die Authentifizierung des Benutzers und lädt den Access Token.
        """
        # Falls ein Token im session_state vorhanden ist, keine erneute Authentifizierung
        if "token" in st.session_state and "access_token" in st.session_state["token"]:
            return

        # Prüfen, ob ein Autorisierungscode in der URL enthalten ist
        auth_code = st.experimental_get_query_params().get("code")
        if auth_code:
            token_data = self.authenticate_user(auth_code[0])
            if token_data:
                # Speichere den Access Token und den Refresh Token im Session State
                st.session_state["token"] = {
                    "access_token": token_data["access_token"],
                    "refresh_token": token_data.get("refresh_token")
                }
                # Speichere Tokens auch im Cookie
                self.save_tokens_to_cookies(token_data["access_token"], token_data.get("refresh_token"))
        else:
            # Keine Authentifizierung vorhanden, leite zum Login weiter
            self.oidc_login()

    def oidc_login(self):
        """ Erstellt die OIDC-Login-URL und leitet den Benutzer zur Keycloak-Login-Seite weiter """
        auth_url = (
            f"{self.authority}/protocol/openid-connect/auth"
            f"?client_id={self.client_id}"
            f"&response_type=code"
            f"&scope={self.scope}"
            f"&redirect_uri={self.redirect_uri}"
        )
        st.markdown(f"[Login mit OIDC]({auth_url})")
        st.stop()

    def check_role(self, id_token, required_role):
        """Überprüft, ob der Benutzer die erforderliche Rolle hat."""
        claims = jwt.get_unverified_claims(id_token)
        roles = claims.get("resource_access", {}).get(self.client_id, {}).get("roles", [])
        return required_role in roles

    def is_token_expired(self, access_token):
        """
        Überprüft, ob der Access Token abgelaufen ist.
        """
        claims = jwt.get_unverified_claims(access_token)
        exp = claims.get("exp")
        if not exp:
            return True
        expiration_time = datetime.fromtimestamp(exp, tz=timezone.utc)
        return datetime.now(timezone.utc) > expiration_time
