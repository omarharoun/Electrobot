import streamlit as st
from openai import OpenAI
import time
import sqlite3
import bcrypt
import os 
os.environ["OPENAI_API_KEY"] == st.secrets["OPENAI_API_KEY"]
os.environ["assistant_id"] == st.secrets["assistant_id"]

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
        return result[1] # Return thread_id
    return None

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
                    st.session_state.thread_id = create_user(username, password)
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
        prompt = st.chat_input("Say something")
        if prompt:
            # Add user message to chat history
            st.session_state.messages.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            with st.chat_message("assistant"):
                message_placeholder = st.empty()
                full_response = ""

                try:
                    # Add user message to thread
                    client.beta.threads.messages.create(
                        thread_id=st.session_state.thread_id,
                        role="user",
                        content=prompt
                    )
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

                    # Retrieve the assistant's response
                    messages = client.beta.threads.messages.list(
                        thread_id=st.session_state.thread_id
                    )
                    for message in reversed(messages.data):
                        if message.role == "assistant":
                            full_response = message.content[0].text.value
                            break

                    message_placeholder.markdown(full_response)
                    st.session_state.messages.append({"role": "assistant", "content": full_response})
                except Exception as e:
                    st.error(f"Error: {str(e)}")
    else:
        st.write("Please log in to start chatting.")

if __name__ == "__main__":
    main()
