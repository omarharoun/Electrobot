import streamlit as st
from openai import OpenAI, Thread
import sqlite3
import bcrypt
import os

# Load environment variables
os.environ["OPENAI_API_KEY"] = st.secrets["OPENAI_API_KEY"]
os.environ["assistant_id"] = st.secrets["assistant_id"]
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
assistant_id = os.getenv("assistant_id")

# Initialize OpenAI Client
client = OpenAI(api_key=OPENAI_API_KEY)

# Database setup
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, thread_id TEXT)''')
    conn.commit()
    conn.close()

def create_user(username, password):
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    thread = client.beta.threads.create()
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO users VALUES (?, ?, ?)", (username, hashed, thread.id))
    conn.commit()
    conn.close()
    return thread.id

def verify_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password, thread_id FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode('utf-8'), result[0]):
        return result[1]  # Return thread_id
    return None

def get_chat_history(thread_id):
    try:
        messages = client.beta.threads.messages.list(thread_id=thread_id)
        return messages.data
    except Exception as e:
        st.error(f"Error retrieving chat history: {str(e)}")
        return []

# Streamlit app
def main():
    st.title("AI Assistant Chat")
    init_db()

    # Sidebar for Login
    st.sidebar.header("Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    login_button = st.sidebar.button("Login")

    # Handle login and main chat interface
    if login_button:
        if username and password:
            thread_id = verify_user(username, password)
            if thread_id:
                st.session_state.thread_id = thread_id
                st.session_state.username = username
                st.success(f"Logged in as {username}")
            else:
                st.session_state.thread_id = create_user(username, password)
                st.session_state.username = username
                st.success(f"New user created: {username}")
        else:
            st.error("Please enter both username and password")

    # Display chat interface if logged in
    if 'username' in st.session_state:
        st.write(f"Logged in as: {st.session_state.username}")

        # Initialize messages in session state
        if 'messages' not in st.session_state:
            st.session_state.messages = []

        # Retrieve and display chat history
        if 'thread_id' in st.session_state:
            chat_history = get_chat_history(st.session_state.thread_id)
            for message in reversed(chat_history):
                role = "user" if message.role == "user" else "assistant"
                content = message.content[0].text.value
                st.session_state.messages.append({"role": role, "content": content})

            # Display chat messages
            for message in st.session_state.messages:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])

            # Chat Input and message handling
            prompt = st.text_input("Ask me anything...", key="input_key")
            if st.button("Send"):
                if prompt:
                    with st.spinner("Thinking..."):
                        try:
                            # Add user message to chat history
                            st.session_state.messages.append({"role": "user", "content": prompt})

                            # Send user message to assistant
                            client_response = client.beta.threads.create_message(thread_id=st.session_state.thread_id, role="user", content={"text": prompt})

                            # Add assistant response to chat history
                            st.session_state.messages.append({"role": "assistant", "content": client_response})

                            # Clear input field after sending message
                            st.session_state.input_key = ""

                        except Exception as e:
                            st.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
