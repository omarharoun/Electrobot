import streamlit as st
from openai import OpenAI
import time
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

# Define allowed username-password pairs
allowed_users = {
    "t": "t",
    "test": "test"
}

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
    if username in allowed_users and password == allowed_users[username]:
        return True
    return False

def get_user_thread_id(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT thread_id FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result:
        return result[0]  # Return thread_id
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
    with st.sidebar:
        st.header("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if username and password:
                if verify_user(username, password):
                    st.session_state.thread_id = get_user_thread_id(username)
                    st.session_state.username = username
                    st.success(f"Logged in as {username}")
                else:
                    st.error("Invalid username or password")
            else:
                st.error("Please enter both username and password")

    # Main chat interface
    if 'username' in st.session_state:
        st.write(f"Logged in as: {st.session_state.username}")
        # Initialize messages in session state
        if 'messages' not in st.session_state:
            st.session_state.messages = []
        
        # Retrieve chat history
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

        # Chat Input and Send Button
        prompt = st.text_input("Say something")
        if st.button("Send"):
            if prompt:
                # Add user message to chat history
                st.session_state.messages.append({"role": "user", "content": prompt})

                with st.spinner("Thinking..."):
                    try:
                        # Send user message to assistant
                        client_response = client.beta.threads.create_message(
                            thread_id=st.session_state.thread_id,
                            role="user",
                            content={"text": prompt}
                        )
                        
                        # Wait for the assistant's response
                        time.sleep(2)  # Adjust this delay as needed
                        assistant_response = ""
                        messages = get_chat_history(st.session_state.thread_id)
                        for message in reversed(messages):
                            if message.role == "assistant":
                                assistant_response = message.content[0].text.value
                                break

                        # Add assistant response to chat history
                        st.session_state.messages.append({"role": "assistant", "content": assistant_response})

                    except Exception as e:
                        st.error(f"Error: {str(e)}")

if __name__ == "__main__":
    main()