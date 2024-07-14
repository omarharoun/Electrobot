import streamlit as st
from openai import OpenAI
import time
import sqlite3
import bcrypt
import os

# Set environment variables using Streamlit secrets management
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
    c.execute('''CREATE TABLE IF NOT EXISTS messages (thread_id TEXT, role TEXT, content TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def create_user(username, password):
    if not is_valid_username(username):
        st.error("Invalid username. Only alphanumeric characters are allowed.")
        return None
    if not is_strong_password(password):
        st.error("Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a digit, and a special character.")
        return None
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    thread = client.beta.threads.create()
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, thread_id) VALUES (?, ?, ?)", (username, hashed, thread.id))
        conn.commit()
    except sqlite3.IntegrityError:
        st.error("Username already exists. Please choose a different username.")
        return None
    finally:
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

def is_valid_username(username):
    return re.match("^[a-zA-Z0-9]+$", username) is not None

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};:'\",<>\.\?\/]", password)
    )

def retrieve_thread_messages(thread_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT role, content FROM messages WHERE thread_id=? ORDER BY timestamp ASC", (thread_id,))
    messages = c.fetchall()
    conn.close()
    return messages

def add_message_to_thread(thread_id, role, content):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (thread_id, role, content) VALUES (?, ?, ?)", (thread_id, role, content))
    conn.commit()
    conn.close()

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
                thread_id = verify_user(username, password)
                if thread_id:
                    st.session_state.thread_id = thread_id
                    st.session_state.username = username
                    st.success(f"Logged in as {username}")
                else:
                    new_thread_id = create_user(username, password)
                    if new_thread_id:
                        st.session_state.thread_id = new_thread_id
                        st.session_state.username = username
                        st.success(f"New user created: {username}")
            else:
                st.error("Please enter both username and password")

    # Main chat interface
    if 'username' in st.session_state:
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
        if prompt:
            # Add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            with st.chat_message("assistant"):
                message_placeholder = st.empty()
                full_response = ""

                try:
                    # Add user message to thread history
                    add_message_to_thread(st.session_state.thread_id, "user", prompt)
                    # Run the assistant
                    run = client.beta.threads.runs.create(
                        thread_id=st.session_state.thread_id,
                        assistant_id=assistant_id
                    )

                    # Wait for the run to complete
                    while run.status != "completed":
                        time.sleep(1)
                        run = client.beta.threads.runs.retrieve(
                            thread_id=st.session_state.thread_id,
                            run_id=run.id
                        )

                    # Retrieve and display assistant's response
                    full_response = retrieve_assistant_response(st.session_state.thread_id)
                    if full_response:
                        message_placeholder.markdown(full_response)
                        add_message_to_thread(st.session_state.thread_id, "assistant", full_response)
                    else:
                        st.error("Assistant response not found.")
                except Exception as e:
                    st.error(f"Error: {str(e)}")
    else:
        st.write("Please log in to start chatting.")

if __name__ == "__main__":
    main()
