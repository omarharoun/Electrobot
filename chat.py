import streamlit as st
from openai import OpenAI
import time
import os 

# Load environment variables
os.environ["OPENAI_API_KEY"] = st.secrets["OPENAI_API_KEY"]
os.environ["assistant_id"] = st.secrets["assistant_id"]
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
assistant_id = os.getenv("assistant_id")

# Initialize OpenAI Client
client = OpenAI(api_key=OPENAI_API_KEY)

# Streamlit app
def main():
    st.title("AI Assistant Chat")
    
    # Sidebar for Login
    with st.sidebar:
        st.header("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if username == "test" and password == "test":
                st.session_state.username = username
                st.success(f"Logged in as {username}")
            else:
                st.error("Invalid username or password")

    # Main chat interface
    if 'username' in st.session_state and st.session_state.username == "test":
        st.write(f"Logged in as: {st.session_state.username}")
        # Initialize messages in session state
        if 'messages' not in st.session_state:
            st.session_state.messages = []
        
        # Display chat messages
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        # Chat Input
        prompt = st.text_input("Say something")
        if st.button("Send"):
            if prompt:
                # Add user message to chat history
                st.session_state.messages.append({"role": "user", "content": prompt})
                with st.chat_message("user"):
                    st.markdown(prompt)
                with st.spinner("Thinking..."):
                    try:
                        # Add user message to thread
                        response = client.Completion.create(
                            model="text-davinci-002",
                            prompt=prompt,
                            max_tokens=150
                        )

                        assistant_response = response.choices[0].text.strip()
                        st.session_state.messages.append({"role": "assistant", "content": assistant_response})
                        
                        # Clear input prompt and trigger UI update
                        st.experimental_rerun()

                    except Exception as e:
                        st.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
