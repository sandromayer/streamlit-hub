import streamlit as st
from keycloak_auth.auth import KeycloakAuth

# Initialisiere Keycloak Authentifizierung
auth = KeycloakAuth()

# Titel der App
st.title("OIDC Authentifizierte Streamlit App")

# Beispiel einer Funktion, die geschützt ist
@auth.require_role(['admin', 'test_role'], logic="OR")
@auth.require_role(['admin', 'test_role2'], logic="OR")
def protected_section():
    st.write("Sie haben Zugriff auf diese geschützte Sektion, weil Sie die erforderliche Rolle besitzen.")

# Zeige die geschützte Sektion an
protected_section()

# Normale Sektion der App
st.write("Dies ist eine öffentliche Sektion der App.")
