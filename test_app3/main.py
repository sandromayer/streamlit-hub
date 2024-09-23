import streamlit as st
from keycloak_auth.auth import KeycloakAuth

# Initialisiere Keycloak Authentifizierung
auth = KeycloakAuth()

# Titel der App
st.title("OIDC Authentifizierte Streamlit App")

# Beispiel einer Funktion mit zwei Gruppen von Rollen:
# - Gruppe 1: Der Benutzer muss "a" ODER "b" haben.
# - Gruppe 2: Der Benutzer muss "c" ODER "d" haben.
@auth.require_any_role(["test_role"])
@auth.require_any_role(["test_role"])
def protected_section():
    st.write("Sie haben Zugriff, weil Sie mindestens eine Rolle aus jeder Gruppe besitzen.")

# Rufe die Funktion auf
protected_section()
