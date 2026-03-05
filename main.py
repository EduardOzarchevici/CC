import sqlite3
import json
import hashlib
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

DB_NAME = "api_database.db"


# --- 1. Database & Auth Helpers ---

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Users table includes a token for simple authentication
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            token TEXT
        )
    ''')
    # Posts table is linked to users via user_id
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()


def hash_password(password):
    """Simple SHA-256 hash (use bcrypt in production via external library)."""
    return hashlib.sha256(password.encode()).hexdigest()


def get_user_from_token(headers):
    """Extracts token from Authorization header and finds the user."""
    auth_header = headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users WHERE token = ?", (token,))
    user = cursor.fetchone()
    conn.close()
    return {"id": user[0], "username": user[1]} if user else None


# --- 2. Request Handler ---

class APIHandler(BaseHTTPRequestHandler):

    def _send_response(self, status_code, data):
        """Helper to send JSON responses."""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def _get_body(self):
        """Helper to safely read and parse JSON body."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0: return {}
            body = self.rfile.read(content_length).decode('utf-8')
            return json.loads(body)
        except Exception:
            return None

    def _parse_path(self):
        """Extracts the resource and ID from the URL (e.g., /posts/5 -> 'posts', '5')."""
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split('/') if p]
        resource = parts[0] if len(parts) > 0 else None
        item_id = parts[1] if len(parts) > 1 else None
        return resource, item_id

    # --- HTTP METHODS ---

    def do_POST(self):
        resource, item_id = self._parse_path()
        body = self._get_body()

        if not body:
            return self._send_response(400, {"error": "Invalid or missing JSON body"})

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        try:
            if resource == 'register' or (resource == 'users' and not item_id):
                # /register AND /users (POST) do the same thing: create a user
                username, password = body['username'], body['password']
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                               (username, hash_password(password)))
                conn.commit()
                self._send_response(201, {"message": "User created", "id": cursor.lastrowid})

            elif resource == 'login':
                username, password = body['username'], hash_password(body['password'])
                cursor.execute("SELECT id FROM users WHERE username = ? AND password = ?", (username, password))
                user = cursor.fetchone()

                if user:
                    token = secrets.token_hex(16)  # Generate a random access token
                    cursor.execute("UPDATE users SET token = ? WHERE id = ?", (token, user[0]))
                    conn.commit()
                    self._send_response(200, {"message": "Login successful", "token": token})
                else:
                    self._send_response(401, {"error": "Invalid credentials"})

            elif resource == 'posts':
                user = get_user_from_token(self.headers)
                if not user: return self._send_response(401, {"error": "Unauthorized"})

                cursor.execute("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
                               (user['id'], body['title'], body['content']))
                conn.commit()
                self._send_response(201, {"message": "Post created", "id": cursor.lastrowid})

            else:
                self._send_response(404, {"error": "Not Found"})

        except sqlite3.IntegrityError:
            self._send_response(409, {"error": "Username already exists"})
        except KeyError as e:
            self._send_response(400, {"error": f"Missing field: {str(e)}"})
        finally:
            conn.close()

    def do_GET(self):
        resource, item_id = self._parse_path()
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        if resource == 'users':
            if item_id:
                cursor.execute("SELECT id, username FROM users WHERE id = ?", (item_id,))
                row = cursor.fetchone()
                if row:
                    self._send_response(200, {"id": row[0], "username": row[1]})
                else:
                    self._send_response(404, {"error": "User not found"})
            else:
                cursor.execute("SELECT id, username FROM users")
                users = [{"id": r[0], "username": r[1]} for r in cursor.fetchall()]
                self._send_response(200, users)

        elif resource == 'posts':
            if item_id:
                cursor.execute("SELECT id, user_id, title, content FROM posts WHERE id = ?", (item_id,))
                row = cursor.fetchone()
                if row:
                    self._send_response(200, {"id": row[0], "user_id": row[1], "title": row[2], "content": row[3]})
                else:
                    self._send_response(404, {"error": "Post not found"})
            else:
                cursor.execute("SELECT id, user_id, title, content FROM posts")
                posts = [{"id": r[0], "user_id": r[1], "title": r[2], "content": r[3]} for r in cursor.fetchall()]
                self._send_response(200, posts)
        else:
            self._send_response(404, {"error": "Not Found"})

        conn.close()

    def _handle_update(self, method):
        """Shared logic for PUT (replace) and PATCH (partial update)."""
        resource, item_id = self._parse_path()
        if not item_id:
            return self._send_response(400, {"error": "ID required for updates"})

        body = self._get_body()
        if not body:
            return self._send_response(400, {"error": "Body required"})

        # Basic Auth Check for updating posts
        if resource == 'posts':
            user = get_user_from_token(self.headers)
            if not user: return self._send_response(401, {"error": "Unauthorized"})

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Dynamically build the SQL UPDATE query
        set_clause = []
        values = []
        for key, value in body.items():
            if key in ('id', 'user_id'): continue  # Prevent updating primary/foreign keys
            # If PUT, we ideally validate that ALL fields are present.
            # For brevity in this raw example, we just update provided fields for both PUT and PATCH.
            if key == 'password': value = hash_password(value)
            set_clause.append(f"{key} = ?")
            values.append(value)

        if not set_clause:
            return self._send_response(400, {"error": "No valid fields to update"})

        values.append(item_id)
        query = f"UPDATE {resource} SET {', '.join(set_clause)} WHERE id = ?"

        cursor.execute(query, values)
        conn.commit()

        if cursor.rowcount == 0:
            self._send_response(404, {"error": "Record not found"})
        else:
            self._send_response(200, {"message": f"Record updated via {method}"})

        conn.close()

    def do_PUT(self):
        self._handle_update("PUT")

    def do_PATCH(self):
        self._handle_update("PATCH")

    def do_DELETE(self):
        resource, item_id = self._parse_path()
        if not item_id: return self._send_response(400, {"error": "ID required"})

        if resource == 'posts':
            user = get_user_from_token(self.headers)
            if not user: return self._send_response(401, {"error": "Unauthorized"})

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM {resource} WHERE id = ?", (item_id,))
        conn.commit()

        if cursor.rowcount == 0:
            self._send_response(404, {"error": "Record not found"})
        else:
            self._send_response(200, {"message": "Record deleted"})
        conn.close()


# --- 3. Server Startup ---

if __name__ == '__main__':
    init_db()
    server = HTTPServer(('', 8000), APIHandler)
    print("REST API running on http://localhost:8000...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
    print("\nServer stopped.")