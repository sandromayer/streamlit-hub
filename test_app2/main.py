import streamlit as st

def main():
    # Set the title of the web app
    st.title("Hello World Streamlit App")

    # Display "Hello World" on the page
    st.write("Hello, World!")

    # Add an input field for users
    name = st.text_input("Enter your name:", "")

    # If a name is entered, display a greeting
    if name:
        st.write(f"Hello, {name}!")

if __name__ == "__main__":
    main()
