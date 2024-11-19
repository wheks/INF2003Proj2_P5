import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd
import matplotlib.pyplot as plt
from pymongo import MongoClient, ASCENDING
import threading
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta, timezone
import psutil
import time
import os
import sys
import numpy as np
from functools import wraps

#Declare global variables at module level
mongo_manager = None
current_user_id = None


def connect_to_databases():
    global mongo_manager, current_user_id
    try:
        #Initialize MongoDB Manager
        mongo_manager = MongoDBManager()

        #Generate a unique user ID for the session
        current_user_id = str(uuid.uuid4())

        print("Database connection established successfully")
        return mongo_manager, current_user_id

    except Exception as e:
        error_message = f"Database Connection Error: {str(e)}"
        print(error_message)
        messagebox.showerror("Database Error", error_message)
        sys.exit(1)


class DatabaseLock:
    def __init__(self):
        self.client = MongoClient(
            "mongodb+srv://INF2003:INF2003@cluster0.yib8q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
        self.db = self.client['passenger_system']
        self.active_users = self.db['active_users']
        self.active_users.create_index([("timestamp", ASCENDING)], expireAfterSeconds=300)
        self.sg_timezone = timezone(timedelta(hours=8))

    def can_open_window(self, user_id, operation_type):
        try:
            current_time = datetime.now(self.sg_timezone)

            result = self.active_users.find_one_and_update(
                {
                    "$or": [
                        {"user_id": user_id},
                        {"timestamp": {"$lt": current_time - timedelta(minutes=5)}},
                        {"user_id": None}
                    ]
                },
                {
                    "$set": {
                        "user_id": user_id,
                        "operation": operation_type,
                        "timestamp": current_time
                    }
                },
                upsert=True,
                return_document=True
            )

            if result and result.get('user_id') == user_id:
                return True, "Access granted"

            lock_info = self.active_users.find_one({})
            if lock_info:
                lock_time = lock_info['timestamp'].replace(tzinfo=timezone.utc).astimezone(self.sg_timezone)
                lock_time_str = lock_time.strftime("%H:%M:%S")
                return False, f"Database is locked by {lock_info['user_id']}\nOperation: {lock_info['operation']}\nLocked since: {lock_time_str} (SGT)"

            return False, "Access denied"

        except Exception as e:
            print(f"Error in can_open_window: {e}")
            return False, f"System error: {str(e)}"

    def release_window(self, user_id):
        try:
            result = self.active_users.delete_one({"user_id": user_id})
            return result.deleted_count > 0
        except Exception as e:
            print(f"Error in release_window: {e}")
            return False

    def get_lock_status(self):
        try:
            lock_info = self.active_users.find_one({})
            if lock_info and lock_info.get('timestamp'):
                lock_time = lock_info['timestamp'].replace(tzinfo=timezone.utc).astimezone(self.sg_timezone)
                lock_time_str = lock_time.strftime("%H:%M:%S")
                return {
                    "locked_by": lock_info.get('user_id'),
                    "operation": lock_info.get('operation'),
                    "timestamp": f"{lock_time_str} (SGT)",
                    "window_open": True
                }
            return {
                "locked_by": None,
                "operation": None,
                "timestamp": None,
                "window_open": False
            }
        except Exception as e:
            print(f"Error in get_lock_status: {e}")
            return {
                "locked_by": None,
                "operation": None,
                "timestamp": None,
                "window_open": False
            }


class AuthManager:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(AuthManager, cls).__new__(cls)
            cls._instance.SECRET_KEY = os.environ.get('APP_SECRET_KEY', 'your-secure-secret-key-here')
        return cls._instance

    def __init__(self):
        if not hasattr(self, 'client'):
            self.client = MongoClient(
                "mongodb+srv://INF2003:INF2003@cluster0.yib8q.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
            self.db = self.client['passenger_system']
            self.users = self.db['users']
            self.create_indexes()

    def create_indexes(self):
        self.users.create_index([("username", ASCENDING)], unique=True)
        self.users.create_index([("email", ASCENDING)], unique=True)

    def register_user(self, username, password, email, role='user'):
        try:
            if self.users.find_one({"username": username}):
                return False, "Username already exists"

            if self.users.find_one({"email": email}):
                return False, "Email already exists"

            #Hash the password
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

            user = {
                "_id": str(uuid.uuid4()),  # Generate a unique user ID
                "username": username,
                "password": hashed_password,
                "email": email,
                "role": role,
                "created_at": datetime.now(timezone.utc),
                "last_login": None,
                "active": True
            }

            self.users.insert_one(user)
            return True, "User registered successfully"

        except Exception as e:
            print(f"Registration error: {str(e)}")
            return False, f"Registration error: {str(e)}"

    def login_user(self, username, password):
        try:
            #Find the user
            user = self.users.find_one({"username": username})
            if not user:
                return False, "Invalid username or password"

            #Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
                return False, "Invalid username or password"

            #Update last login
            self.users.update_one(
                {"username": username},
                {"$set": {"last_login": datetime.now(timezone.utc)}}
            )

            #Create JWT payload
            payload = {
                'user_id': username,
                'username': username,
                'role': user.get('role', 'user'),
                'exp': datetime.now(timezone.utc) + timedelta(hours=24)
            }

            try:
                #Generate token with explicit algorithm
                token = jwt.encode(
                    payload,
                    self.SECRET_KEY,
                    algorithm='HS256'
                )
                return True, token
            except Exception as e:
                print(f"Token generation error: {str(e)}")
                return False, "Error generating authentication token"

        except Exception as e:
            print(f"Login error: {str(e)}")
            return False, f"Login error: {str(e)}"

    def verify_token(self, token):
        try:
            payload = jwt.decode(
                token,
                self.SECRET_KEY,
                algorithms=['HS256']
            )
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, "Token has expired"
        except jwt.InvalidTokenError:
            return False, "Invalid token"
        except Exception as e:
            print(f"Token verification error: {str(e)}")
            return False, "Error verifying token"


#Modify the LoginWindow's login method
class LoginWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Login - Passenger Management System")
        self.root.geometry("600x500")
        self.auth_manager = AuthManager()

        # Initialize entry attributes
        self.username_entry = None
        self.password_entry = None
        self.setup_ui()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return

        success, result = self.auth_manager.login_user(username, password)
        if success:
            try:
                #Verify the token immediately after login to ensure it's valid
                verify_success, _ = self.auth_manager.verify_token(result)
                if verify_success:
                    self.root.destroy()
                    start_main_application(result)
                else:
                    messagebox.showerror("Login Failed", "Session validation failed")
            except Exception as e:
                print(f"Token verification error: {e}")
                messagebox.showerror("Login Failed", "Session validation failed")
        else:
            messagebox.showerror("Login Failed", result)

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Passenger Management System",
                  font=('Helvetica', 12, 'bold')).pack(pady=10)

        login_frame = ttk.LabelFrame(main_frame, text="Login", padding="10")
        login_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        ttk.Label(login_frame, text="Username:").pack(pady=5)
        self.username_entry = ttk.Entry(login_frame)
        self.username_entry.pack(fill=tk.X, pady=5)

        ttk.Label(login_frame, text="Password:").pack(pady=5)
        self.password_entry = ttk.Entry(login_frame, show="*")
        self.password_entry.pack(fill=tk.X, pady=5)

        ttk.Button(login_frame, text="Login",
                   command=self.login).pack(pady=20)

        register_frame = ttk.LabelFrame(main_frame, text="Register", padding="10")
        register_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        ttk.Button(register_frame, text="Create New Account",
                   command=self.show_register_window).pack(pady=10)

    def show_register_window(self):
        register_window = tk.Toplevel(self.root)
        register_window.title("Register New Account")
        register_window.geometry("300x400")

        frame = ttk.Frame(register_window, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Username:").pack(pady=5)
        username_entry = ttk.Entry(frame)
        username_entry.pack(fill=tk.X, pady=5)

        ttk.Label(frame, text="Email:").pack(pady=5)
        email_entry = ttk.Entry(frame)
        email_entry.pack(fill=tk.X, pady=5)

        ttk.Label(frame, text="Password:").pack(pady=5)
        password_entry = ttk.Entry(frame, show="*")
        password_entry.pack(fill=tk.X, pady=5)

        ttk.Label(frame, text="Confirm Password:").pack(pady=5)
        confirm_pass_entry = ttk.Entry(frame, show="*")
        confirm_pass_entry.pack(fill=tk.X, pady=5)

        def register():
            username = username_entry.get()
            email = email_entry.get()
            password = password_entry.get()
            confirm_pass = confirm_pass_entry.get()

            if not all([username, email, password, confirm_pass]):
                messagebox.showerror("Error", "Please fill all fields")
                return

            if password != confirm_pass:
                messagebox.showerror("Error", "Passwords do not match")
                return

            success, message = self.auth_manager.register_user(username, password, email)
            if success:
                messagebox.showinfo("Success", message)
                register_window.destroy()
            else:
                messagebox.showerror("Registration Failed", message)

        ttk.Button(frame, text="Register", command=register).pack(pady=20)

    def run(self):
        self.root.mainloop()


class MainApplication:
    def __init__(self, token):
        self.root = tk.Tk()
        self.root.title("Passenger Management System")
        self.root.geometry("400x600")

        #Initialize managers
        self.auth_manager = AuthManager()
        self.mongo_manager = MongoDBManager()
        self.db_lock = DatabaseLock()

        #Verify token using AuthManager
        success, payload = self.auth_manager.verify_token(token)
        if not success:
            messagebox.showerror("Error", "Invalid session. Please login again.")
            self.root.destroy()
            start_login()
            return

        #Store user information from verified payload
        self.user_info = payload
        self.username = payload.get('username', 'Unknown User')

        #Store username globally
        global current_user_id, current_username
        current_user_id = self.username
        current_username = self.username

        #Set up the UI
        self.setup_main_menu()

        #Start periodic status checks
        self.root.after(1000, self.check_status)

    def setup_main_menu(self):
        #Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        #Create main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        #Create enhanced status display at the top
        self.create_enhanced_status_display(main_frame)

        #Header with user info
        ttk.Label(main_frame,
                  text=f"Logged in as: {self.username}",
                  font=('Helvetica', 10)).pack(pady=5)

        ttk.Label(main_frame,
                  text="Passenger Management System",
                  font=('Helvetica', 12, 'bold')).pack(pady=10)

        #Create sections
        self.create_passenger_section(main_frame)
        self.create_analysis_section(main_frame)
        self.create_system_section(main_frame)

    def create_enhanced_status_display(self, parent):
        """Create an enhanced status display showing database lock and user information"""
        #Create status frame
        self.status_frame = ttk.LabelFrame(parent, text="System Status", padding="10")
        self.status_frame.pack(fill=tk.X, pady=5)

        #Create status label with more detailed information
        self.status_label = ttk.Label(
            self.status_frame,
            text="Initializing system status...",
            font=('Helvetica', 9),
            wraplength=350
        )
        self.status_label.pack(fill=tk.X, padx=5, pady=5)

    def update_status_display(self, status):
        try:
            if status["locked_by"]:
                status_text = (
                    f"Database locked by: {status['locked_by']}\n"
                    f"Operation: {status['operation']}\n"
                    f"Locked since: {status['timestamp']}"
                )
                self.status_label.configure(
                    text=status_text,
                    foreground='red'
                )
                if status["locked_by"] != self.username:
                    self.set_buttons_state('disabled')
                else:
                    self.set_buttons_state('normal')
            else:
                self.status_label.configure(
                    text="✓ Database available",
                    foreground='green'
                )
                self.set_buttons_state('normal')
        except Exception as e:
            print(f"Error updating status display: {e}")

    def check_status(self):
        """Periodic status check"""
        try:
            status = self.db_lock.get_lock_status()
            self.update_status_display(status)
        except Exception as e:
            print(f"Error checking status: {e}")
        finally:
            #Schedule next check
            self.root.after(1000, self.check_status)

    def safe_check_and_open(self, window_func, operation_type):
        """Safely check lock and open window"""
        try:
            # Check if operation can be performed
            status = self.db_lock.get_lock_status()
            if status["locked_by"] and status["locked_by"] != self.username:
                return  # Silently return if another user has the lock

            success, message = self.db_lock.can_open_window(self.username, operation_type)
            if not success:
                messagebox.showerror("Operation Blocked", message)
                return

            # Schedule the window opening in the main thread
            self.root.after(1, window_func)
        except Exception as e:
            self.db_lock.release_window(self.username)
            messagebox.showerror("Error", f"Failed to open window: {str(e)}")

    def set_buttons_state(self, state):
        """Set button states safely"""
        try:
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Frame):
                    for child in widget.winfo_children():
                        if isinstance(child, ttk.Button) and child.cget('text') != 'Logout':
                            child.configure(state=state)
        except Exception as e:
            print(f"Error setting button states: {e}")

    def create_passenger_section(self, parent):
        """Create the passenger management section with direct button creation"""
        try:
            section_frame = ttk.LabelFrame(parent, text="Passenger Management", padding="10")
            section_frame.pack(fill=tk.X, pady=5)

            #Create buttons directly
            ttk.Button(section_frame,
                       text="Create New Passenger",
                       command=lambda: self.safe_check_and_open(open_create_passen_window, "CREATE")
                       ).pack(fill=tk.X, pady=2)

            ttk.Button(section_frame,
                       text="Read Passenger Details",
                       command=lambda: self.safe_check_and_open(open_read_passen_window, "READ")
                       ).pack(fill=tk.X, pady=2)

            ttk.Button(section_frame,
                       text="Update Passenger",
                       command=lambda: self.safe_check_and_open(open_update_passen_window, "UPDATE")
                       ).pack(fill=tk.X, pady=2)

            ttk.Button(section_frame,
                       text="Delete Passenger",
                       command=lambda: self.safe_check_and_open(open_delete_passen_window, "DELETE")
                       ).pack(fill=tk.X, pady=2)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create passenger section: {str(e)}")

    def safe_check_and_open(self, window_func, operation_type):
        """Safely check lock and open window"""
        try:
            #Check if operation can be performed
            success, message = self.db_lock.can_open_window(self.username, operation_type)
            if not success:
                messagebox.showerror("Operation Blocked", message)
                return

            #Schedule the window opening in the main thread
            self.root.after(1, window_func)
        except Exception as e:
            self.db_lock.release_window(self.username)
            messagebox.showerror("Error", f"Failed to open window: {str(e)}")

    def create_analysis_section(self, parent):
        """Create the analysis tools section"""
        section_frame = ttk.LabelFrame(parent, text="Analysis Tools", padding="10")
        section_frame.pack(fill=tk.X, pady=5)

        ttk.Button(section_frame,
                   text="Analyse Airline Popularity",
                   command=analyse_airline_popularity).pack(fill=tk.X, pady=2)
        ttk.Button(section_frame,
                   text="Analyse Tourism Duration",
                   command=analyse_tourism_duration).pack(fill=tk.X, pady=2)
        ttk.Button(section_frame,
                   text="Analyse Airline Trend",
                   command=analyse_airline_trend).pack(fill=tk.X, pady=2)

    def create_system_section(self, parent):
        """Create the system section"""
        section_frame = ttk.LabelFrame(parent, text="System", padding="10")
        section_frame.pack(fill=tk.X, pady=5)

        ttk.Button(section_frame,
                   text="Logout",
                   command=self.logout).pack(fill=tk.X, pady=2)

    def logout(self):
        """Handle user logout"""
        if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
            #Release any locks held by this user
            self.db_lock.release_window(self.username)
            self.root.destroy()
            start_login()

    def run(self):
        """Start the main application loop"""
        self.root.mainloop()

    def __del__(self):
        """Cleanup when the application is destroyed"""
        try:
            self.db_lock.release_window(self.username)
        except:
            pass


#MongoDB Connection
class MongoDBManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(MongoDBManager, cls).__new__(cls)
                cls._instance.db_lock = DatabaseLock()  # Use singleton DatabaseLock
            return cls._instance

    def __init__(self):
        if not hasattr(self, 'client'):
            self.client = MongoClient(
                "mongodb+srv://INF2003:INF2003@cluster0.yib8q.mongodb.net/"
                "?retryWrites=true&w=majority&appName=Cluster0")
            self.db = self.client['passenger_system']
            self.passengers = self.db['passengers']
            self.airlines = self.db['airlines']
            self.countries = self.db['countries']
            self.length_of_stay = self.db['length_of_stay']
            self.active_users = self.db['active_users']
            self.create_indexes()

    def require_database_lock(self, operation_type):
        """Decorator for database operations that require locking"""

        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                user_id = kwargs.get('user_id', current_user_id)
                username = kwargs.get('username', current_username)

                if not user_id:
                    raise ValueError("User ID not provided for database operation")

                # Try to acquire lock
                success, message = self.db_lock.acquire(user_id, operation_type)
                if not success:
                    messagebox.showerror("Database Locked", message)
                    return None

                try:
                    # Execute the operation if lock was acquired
                    result = func(*args, **kwargs)
                    return result
                finally:
                    # Always release the lock after operation
                    self.db_lock.release(user_id)

            return wrapper

        return decorator

    def create_indexes(self):
        # Create indexes for better query performance
        self.passengers.create_index([("pid", ASCENDING)], unique=True)
        self.passengers.create_index([("name", ASCENDING)])
        self.airlines.create_index([("aid", ASCENDING)], unique=True)
        self.countries.create_index([("cid", ASCENDING)], unique=True)
        self.length_of_stay.create_index([("lid", ASCENDING)], unique=True)

    def create_passenger(self, name, age, gender, lid, aid, cid, user_id=None):
        @self.require_database_lock("CREATE")
        def create_impl(name, age, gender, lid, aid, cid, user_id=None):
            try:
                # Find the first available PID
                existing_pids = set(doc['pid'] for doc in self.passengers.find({}, {'pid': 1}))
                new_pid = 1
                while new_pid in existing_pids:
                    new_pid += 1

                # Create passenger document
                passenger_data = {
                    "pid": new_pid,
                    "name": name,
                    "age": int(age),
                    "gender": gender,
                    "lid": lid,
                    "aid": aid,
                    "cid": cid,
                    "created_at": datetime.now(timezone.utc)
                }

                # Input validation
                if not name or not name.strip():
                    return False, "Name cannot be empty", None

                try:
                    age = int(age)
                    if age < 0 or age > 150:
                        return False, "Age must be between 0 and 150", None
                except ValueError:
                    return False, "Age must be a valid number", None

                if not all([gender, lid, aid, cid]):
                    return False, "All fields must be filled", None

                # Insert passenger and update counters in a transaction
                with self.client.start_session() as session:
                    with session.start_transaction():
                        # Insert the passenger
                        self.passengers.insert_one(passenger_data, session=session)

                        # Update counters
                        self.length_of_stay.update_one(
                            {"lid": lid},
                            {"$inc": {"loscount": 1}},
                            session=session
                        )
                        self.airlines.update_one(
                            {"aid": aid},
                            {"$inc": {"acount": 1}},
                            session=session
                        )
                        self.countries.update_one(
                            {"cid": cid},
                            {"$inc": {"ccount": 1}},
                            session=session
                        )

                return True, "Passenger created successfully", new_pid

            except Exception as e:
                print(f"Error creating passenger: {e}")
                return False, f"Failed to create passenger: {e}", None

        return create_impl(name, age, gender, lid, aid, cid, user_id)

    def read_passengers(self, search_by="All", pid=None, user_id=None):
        @self.require_database_lock("READ")
        def read_impl(search_by="All", pid=None, user_id=None):
            try:
                results = []
                if search_by == "PID":
                    if not pid:
                        return False, "Please enter a PID", None
                    try:
                        pid = int(pid)
                        passenger = self.passengers.find_one({"pid": pid}, {'_id': 0})
                        if passenger:
                            # Convert datetime objects to string format
                            for key, value in passenger.items():
                                if isinstance(value, datetime):
                                    passenger[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                            results = [passenger]
                        else:
                            return False, f"No passenger found with PID: {pid}", None
                    except ValueError:
                        return False, "PID must be a number", None
                else:  # "All" option
                    # Get all passengers and format datetime fields
                    cursor = self.passengers.find({}, {'_id': 0})
                    for passenger in cursor:
                        # Convert datetime objects to string format
                        for key, value in passenger.items():
                            if isinstance(value, datetime):
                                passenger[key] = value.strftime("%Y-%m-%d %H:%M:%S")
                        results.append(passenger)

                if not results:
                    return False, "No matching passengers found", None

                # Return the success message and results
                return True, f"Found {len(results)} passenger(s)", results

            except Exception as e:
                error_msg = str(e)
                print(f"Error reading passengers: {error_msg}")
                return False, f"Failed to read passengers: {error_msg}", None

        # Call the implementation with the provided arguments
        result = read_impl(search_by=search_by, pid=pid, user_id=user_id)
        return result

    def update_passenger(self, pid, updates, user_id=None):
        @self.require_database_lock("UPDATE")
        def update_impl(pid, updates, user_id=None):
            try:
                if not pid:
                    return False, "Passenger ID cannot be empty"

                # Find current passenger data
                old_passenger = self.passengers.find_one({"pid": int(pid)})
                if not old_passenger:
                    return False, f"No passenger found with ID: {pid}"

                # Validate age if it's being updated
                if 'age' in updates:
                    try:
                        age = int(updates['age'])
                        if age < 0 or age > 150:
                            return False, "Age must be between 0 and 150"
                        updates['age'] = age
                    except ValueError:
                        return False, "Age must be a valid number"

                # Add updated_at timestamp
                updates["updated_at"] = datetime.now(timezone.utc)

                # Update passenger and adjust counters in a transaction
                with self.client.start_session() as session:
                    with session.start_transaction():
                        # Update the passenger
                        result = self.passengers.update_one(
                            {"pid": int(pid)},
                            {"$set": updates},
                            session=session
                        )

                        if result.modified_count == 0:
                            return False, "No changes made to passenger record"

                        # Update counters only if reference fields changed
                        if 'lid' in updates and old_passenger['lid'] != updates['lid']:
                            self.length_of_stay.update_one(
                                {"lid": old_passenger['lid']},
                                {"$inc": {"loscount": -1}},
                                session=session
                            )
                            self.length_of_stay.update_one(
                                {"lid": updates['lid']},
                                {"$inc": {"loscount": 1}},
                                session=session
                            )

                        if 'aid' in updates and old_passenger['aid'] != updates['aid']:
                            self.airlines.update_one(
                                {"aid": old_passenger['aid']},
                                {"$inc": {"acount": -1}},
                                session=session
                            )
                            self.airlines.update_one(
                                {"aid": updates['aid']},
                                {"$inc": {"acount": 1}},
                                session=session
                            )

                        if 'cid' in updates and old_passenger['cid'] != updates['cid']:
                            self.countries.update_one(
                                {"cid": old_passenger['cid']},
                                {"$inc": {"ccount": -1}},
                                session=session
                            )
                            self.countries.update_one(
                                {"cid": updates['cid']},
                                {"$inc": {"ccount": 1}},
                                session=session
                            )

                return True, "Passenger updated successfully"

            except Exception as e:
                print(f"Error updating passenger: {e}")
                return False, f"Failed to update passenger: {e}"

        return update_impl(pid, updates, user_id)

    def delete_passenger(self, pid, user_id=None):
        @self.require_database_lock("DELETE")
        def delete_impl(pid, user_id=None):
            try:
                # Input validation
                if not pid:
                    return False, "Passenger ID cannot be empty"

                try:
                    pid = int(pid)
                except ValueError:
                    return False, "PID must be a number"

                # Find passenger to get reference IDs before deletion
                passenger = self.passengers.find_one({"pid": pid})
                if not passenger:
                    return False, f"No passenger found with ID: {pid}"

                # Delete passenger and update counters in a transaction
                with self.client.start_session() as session:
                    with session.start_transaction():
                        # Delete the passenger
                        result = self.passengers.delete_one({"pid": pid}, session=session)

                        if result.deleted_count == 0:
                            return False, "Failed to delete passenger"

                        # Update counters
                        self.length_of_stay.update_one(
                            {"lid": passenger['lid']},
                            {"$inc": {"loscount": -1}},
                            session=session
                        )
                        self.airlines.update_one(
                            {"aid": passenger['aid']},
                            {"$inc": {"acount": -1}},
                            session=session
                        )
                        self.countries.update_one(
                            {"cid": passenger['cid']},
                            {"$inc": {"ccount": -1}},
                            session=session
                        )

                return True, "Passenger deleted successfully"

            except Exception as e:
                print(f"Error deleting passenger: {e}")
                return False, f"Failed to delete passenger: {e}"

        return delete_impl(pid, user_id)

    def check_operation_access(self, user_id, operation_type):
        return self.db_lock.acquire(user_id, operation_type)

    def release_operation_lock(self, user_id):
        return self.db_lock.release(user_id)

    def get_lock_info(self):
        """Get current lock status including username"""
        status = self.db_lock.get_lock_status()
        if status["locked_by_username"] is None and status["locked_by"] is not None:
            # If we somehow don't have the username but have an ID, show "Unknown User"
            status["locked_by_username"] = "Unknown User"
        return status

# Utility function for getting distinct values from any collection
    def get_valid_options(self, collection_name, field):
        collection = self.db[collection_name]
        return list(collection.distinct(field))

    def get_lid_options(self):
        return self.get_valid_options('length_of_stay', 'lid')

    def get_aid_options(self):
        return self.get_valid_options('airlines', 'aid')

    def get_cid_options(self):
        return self.get_valid_options('countries', 'cid')


# Decorator for operation locking
def require_lock(operation_type):
    def decorator(func):
        def wrapper(*args, **kwargs):
            global current_user_id, mongo_manager

            success, message = mongo_manager.check_operation_access(current_user_id, operation_type)
            if not success:
                messagebox.showerror("Access Denied", message)
                return None

            try:
                result = func(*args, **kwargs)
                return result
            finally:
                mongo_manager.release_operation_lock(current_user_id, operation_type)

        return wrapper

    return decorator


def open_create_passen_window():
    global mongo_manager, current_user_id

    # First check if system is already locked by another user
    status = mongo_manager.db_lock.get_lock_status()
    if status["locked_by"] and status["locked_by"] != current_user_id:
        return  # Silently return if another user has the lock

    # Then check if window can be opened
    can_open, message = mongo_manager.db_lock.can_open_window(
        current_user_id,
        "CREATE"
    )

    if not can_open:
        messagebox.showerror("Access Denied", message)
        return

    create_window = tk.Toplevel()
    create_window.title("Create New Passenger")
    create_window.geometry("400x400")

    # Add window closing handler
    def on_window_close():
        mongo_manager.db_lock.release_window(current_user_id)
        create_window.destroy()

    create_window.protocol("WM_DELETE_WINDOW", on_window_close)

    frame = ttk.Frame(create_window, padding=20)
    frame.pack(expand=True, fill='both')

    # Name field
    ttk.Label(frame, text="Name:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
    name_entry = ttk.Entry(frame)
    name_entry.grid(row=0, column=1, padx=5, pady=5)

    # Age field
    ttk.Label(frame, text="Age:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
    age_entry = ttk.Entry(frame)
    age_entry.grid(row=1, column=1, padx=5, pady=5)

    # Gender field
    ttk.Label(frame, text="Gender:").grid(row=2, column=0, padx=5, pady=5, sticky='e')
    gender_combobox = ttk.Combobox(frame, values=['M', 'F', 'NB'])
    gender_combobox.grid(row=2, column=1, padx=5, pady=5)

    # LID field
    ttk.Label(frame, text="Length of Stay:").grid(row=3, column=0, padx=5, pady=5, sticky='e')
    lid_combobox = ttk.Combobox(frame, values=mongo_manager.get_lid_options())
    lid_combobox.grid(row=3, column=1, padx=5, pady=5)

    # AID field
    ttk.Label(frame, text="Airline:").grid(row=4, column=0, padx=5, pady=5, sticky='e')
    aid_combobox = ttk.Combobox(frame, values=mongo_manager.get_aid_options())
    aid_combobox.grid(row=4, column=1, padx=5, pady=5)

    # CID field
    ttk.Label(frame, text="Country:").grid(row=5, column=0, padx=5, pady=5, sticky='e')
    cid_combobox = ttk.Combobox(frame, values=mongo_manager.get_cid_options())
    cid_combobox.grid(row=5, column=1, padx=5, pady=5)

    def perform_create():
        start_time = time.time()
        initial_memory = psutil.virtual_memory().used / (1024 ** 2)

        try:
            # Get values from fields
            values = {
                "name": name_entry.get().strip(),
                "age": age_entry.get().strip(),
                "gender": gender_combobox.get(),
                "lid": lid_combobox.get(),
                "aid": aid_combobox.get(),
                "cid": cid_combobox.get()
            }

            success, message, new_pid = mongo_manager.create_passenger(**values)

            # Calculate performance metrics
            end_time = time.time()
            final_memory = psutil.virtual_memory().used / (1024 ** 2)
            execution_time = round(end_time - start_time, 5)
            memory_used = max(0, round(final_memory - initial_memory, 5))

            if success:
                messagebox.showinfo(
                    "Success",
                    f"Passenger created successfully with ID: {new_pid}\n\n"
                    f"Performance Metrics:\n"
                    f"Time: {execution_time} seconds\n"
                    f"Memory: {memory_used} MB"
                )
                create_window.destroy()
            else:
                messagebox.showerror("Error", message)

            mongo_manager.db_lock.release_window(current_user_id)
            create_window.destroy()

        except Exception as e:
            mongo_manager.db_lock.release_window(current_user_id)
            messagebox.showerror("Error", str(e))
            create_window.destroy()

    # Create button
    ttk.Button(frame, text="Create Passenger",
               command=perform_create).grid(row=6, column=0, columnspan=2, pady=20)


def open_read_passen_window():
    global mongo_manager, current_user_id

    status = mongo_manager.db_lock.get_lock_status()
    if status["locked_by"] and status["locked_by"] != current_user_id:
        return

    can_open, message = mongo_manager.db_lock.can_open_window(
        current_user_id,
        "READ"
    )

    if not can_open:
        messagebox.showerror("Access Denied", message)
        return

    read_window = tk.Toplevel()
    read_window.title("Read Passenger Details")
    read_window.geometry("600x600")

    main_frame = ttk.Frame(read_window, padding=10)
    main_frame.pack(fill='both', expand=True)

    # Search options
    search_frame = ttk.Frame(main_frame)
    search_frame.pack(fill='x', pady=10)

    search_by = tk.StringVar(value="All")
    ttk.Radiobutton(search_frame, text="Show All", variable=search_by,
                    value="All").pack(side='left', padx=10)
    ttk.Radiobutton(search_frame, text="Search by PID", variable=search_by,
                    value="PID").pack(side='left', padx=10)

    # PID entry
    pid_frame = ttk.Frame(main_frame)
    pid_frame.pack(fill='x', pady=5)
    ttk.Label(pid_frame, text="Enter PID:").pack(side='left', padx=5)
    pid_entry = ttk.Entry(pid_frame)
    pid_entry.pack(side='left', padx=5)

    # Results area
    result_frame = ttk.Frame(main_frame)
    result_frame.pack(fill='both', expand=True)

    result_text = tk.Text(result_frame, wrap='word', height=15)
    scrollbar = ttk.Scrollbar(result_frame, command=result_text.yview)
    result_text.configure(yscrollcommand=scrollbar.set)
    result_text.pack(side='left', fill='both', expand=True)
    scrollbar.pack(side='right', fill='y')

    def perform_search():
        global mongo_manager, current_user_id
        start_time = time.time()
        initial_memory = psutil.virtual_memory().used / (1024 ** 2)

        result_text.delete('1.0', tk.END)

        try:
            success, message, results = mongo_manager.read_passengers(
                search_by=search_by.get(),
                pid=pid_entry.get().strip() if search_by.get() == "PID" else None,
                user_id=current_user_id  # Add this line
            )

            # Calculate performance metrics
            end_time = time.time()
            final_memory = psutil.virtual_memory().used / (1024 ** 2)
            execution_time = round(end_time - start_time, 5)
            memory_used = max(0, round(final_memory - initial_memory, 5))

            if not success:
                result_text.insert(tk.END, f"{message}\n")
                return

            result_text.insert(tk.END, f"{message}\n")
            result_text.insert(tk.END, "-" * 30 + "\n")

            for passenger in results:
                result_text.insert(tk.END, "\nPassenger Information:\n")
                for key, value in passenger.items():
                    if key != '_id':  # Skip MongoDB's internal ID
                        formatted_value = value
                        if isinstance(value, datetime):
                            formatted_value = value.strftime("%Y-%m-%d %H:%M:%S")
                        result_text.insert(tk.END, f"{key}: {formatted_value}\n")
                result_text.insert(tk.END, "-" * 30 + "\n")

            result_text.insert(tk.END, f"\nPerformance Metrics:\n")
            result_text.insert(tk.END, f"Time: {execution_time} seconds\n")
            result_text.insert(tk.END, f"Memory: {memory_used} MB\n")

            mongo_manager.db_lock.release_window(current_user_id)
            read_window.destroy()

        except Exception as e:
            mongo_manager.db_lock.release_window(current_user_id)
            read_window.destroy()
            print(f"Error occurred: {str(e)}")
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    # Buttons
    button_frame = ttk.Frame(main_frame)
    button_frame.pack(fill='x', pady=10)

    ttk.Button(button_frame, text="Search", command=perform_search).pack(side='left', padx=5)
    ttk.Button(button_frame, text="Close", command=read_window.destroy).pack(side='right', padx=5)

    # Bind Enter key to search
    def on_enter(event):
        perform_search()

    pid_entry.bind('<Return>', on_enter)

    # Set focus to PID entry if "Search by PID" is selected
    def on_search_mode_change(*args):
        if search_by.get() == "PID":
            pid_entry.focus()

    search_by.trace('w', on_search_mode_change)

    # Center the window
    read_window.update_idletasks()
    width = read_window.winfo_width()
    height = read_window.winfo_height()
    x = (read_window.winfo_screenwidth() // 2) - (width // 2)
    y = (read_window.winfo_screenheight() // 2) - (height // 2)
    read_window.geometry(f'{width}x{height}+{x}+{y}')


def open_update_passen_window():
    global mongo_manager, current_user_id

    status = mongo_manager.db_lock.get_lock_status()
    if status["locked_by"] and status["locked_by"] != current_user_id:
        return

    can_open, message = mongo_manager.db_lock.can_open_window(
        current_user_id,
        "UPDATE"
    )

    if not can_open:
        messagebox.showerror("Access Denied", message)
        return

    update_window = tk.Toplevel()
    update_window.title("Update Passenger")
    update_window.geometry("400x450")

    frame = ttk.Frame(update_window, padding="40 20 40 20")  # Left, top, right, bottom padding
    frame.pack(expand=True, fill='both')

    ttk.Label(frame, text="Please only edit the values you would like to change", wraplength=300).grid(
        row=0, column=0, columnspan=2, padx=5, pady=(0, 20), sticky='w')

    # Fields with consistent spacing
    # PID field
    ttk.Label(frame, text="Passenger ID:").grid(row=1, column=0, padx=5, pady=(0, 15), sticky='w')
    pid_entry = ttk.Entry(frame)
    pid_entry.grid(row=1, column=1, padx=5, pady=(0, 15), sticky='w')

    # Name field
    ttk.Label(frame, text="Name:").grid(row=2, column=0, padx=5, pady=(0, 15), sticky='w')
    name_entry = ttk.Entry(frame)
    name_entry.grid(row=2, column=1, padx=5, pady=(0, 15), sticky='w')

    # Age field
    ttk.Label(frame, text="Age:").grid(row=3, column=0, padx=5, pady=(0, 15), sticky='w')
    age_entry = ttk.Entry(frame)
    age_entry.grid(row=3, column=1, padx=5, pady=(0, 15), sticky='w')

    # Gender field
    ttk.Label(frame, text="Gender:").grid(row=4, column=0, padx=5, pady=(0, 15), sticky='w')
    gender_combobox = ttk.Combobox(frame, values=['M', 'F', 'NB'])
    gender_combobox.grid(row=4, column=1, padx=5, pady=(0, 15), sticky='w')

    # Length of Stay field
    ttk.Label(frame, text="Length of Stay ID:").grid(row=5, column=0, padx=5, pady=(0, 15), sticky='w')
    lid_combobox = ttk.Combobox(frame, values=mongo_manager.get_lid_options())
    lid_combobox.grid(row=5, column=1, padx=5, pady=(0, 15), sticky='w')

    # Airline field
    ttk.Label(frame, text="Airline ID:").grid(row=6, column=0, padx=5, pady=(0, 15), sticky='w')
    aid_combobox = ttk.Combobox(frame, values=mongo_manager.get_aid_options())
    aid_combobox.grid(row=6, column=1, padx=5, pady=(0, 15), sticky='w')

    # Country field
    ttk.Label(frame, text="Country ID:").grid(row=7, column=0, padx=5, pady=(0, 15), sticky='w')
    cid_combobox = ttk.Combobox(frame, values=mongo_manager.get_cid_options())
    cid_combobox.grid(row=7, column=1, padx=5, pady=(0, 15), sticky='w')

    def perform_update():
        start_time = time.time()
        initial_memory = psutil.virtual_memory().used / (1024 ** 2)

        try:
            # Validate PID first
            if not pid_entry.get().strip():
                messagebox.showerror("Error", "Please enter a Passenger ID")
                return

            # Collect non-empty fields
            updates = {}
            if name_entry.get().strip():
                updates['name'] = name_entry.get().strip()
            if age_entry.get().strip():
                updates['age'] = age_entry.get().strip()
            if gender_combobox.get():
                updates['gender'] = gender_combobox.get()
            if lid_combobox.get():
                updates['lid'] = lid_combobox.get()
            if aid_combobox.get():
                updates['aid'] = aid_combobox.get()
            if cid_combobox.get():
                updates['cid'] = cid_combobox.get()

            if not updates:
                messagebox.showinfo("Info", "No updates provided")
                return

            success, message = mongo_manager.update_passenger(pid_entry.get().strip(), updates)

            # Calculate performance metrics
            end_time = time.time()
            final_memory = psutil.virtual_memory().used / (1024 ** 2)
            execution_time = round(end_time - start_time, 5)
            memory_used = max(0, round(final_memory - initial_memory, 5))

            if success:
                messagebox.showinfo(
                    "Success",
                    f"{message}\n\n"
                    f"Performance Metrics:\n"
                    f"Time: {execution_time} seconds\n"
                    f"Memory: {memory_used} MB"
                )
                update_window.destroy()
            else:
                messagebox.showerror("Error", message)

            mongo_manager.db_lock.release_window(current_user_id)
            update_window.destroy()

        except Exception as e:
            mongo_manager.db_lock.release_window(current_user_id)
            update_window.destroy()
            messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")

    def on_window_close():
        mongo_manager.db_lock.release_window(current_user_id)
        update_window.destroy()

    update_window.protocol("WM_DELETE_WINDOW", on_window_close)

    ttk.Button(frame, text="Update Passenger",
               command=perform_update).grid(row=8, column=0, columnspan=2, pady=20)


def open_delete_passen_window():
    global mongo_manager, current_user_id

    status = mongo_manager.db_lock.get_lock_status()
    if status["locked_by"] and status["locked_by"] != current_user_id:
        return

    can_open, message = mongo_manager.db_lock.can_open_window(
        current_user_id,
        "DELETE"
    )

    if not can_open:
        messagebox.showerror("Access Denied", message)
        return

    delete_window = tk.Toplevel()
    delete_window.title("Delete Passenger")
    delete_window.geometry("300x200")

    frame = ttk.Frame(delete_window, padding=20)
    frame.pack(expand=True, fill='both')

    # PID Entry Section
    ttk.Label(frame, text="Passenger ID:", font=('Helvetica', 10, 'bold')).pack(pady=5)
    pid_entry = ttk.Entry(frame, width=30)
    pid_entry.pack(pady=5)

    # Status label for feedback
    status_label = ttk.Label(frame, text="", foreground="red")
    status_label.pack(pady=5)

    def perform_delete():
        global mongo_manager
        # Clear previous status
        status_label.config(text="")

        # Get and validate PID
        pid = pid_entry.get().strip()
        if not pid:
            status_label.config(text="Please enter a Passenger ID")
            return

        # Confirm deletion
        if not messagebox.askyesno(
                "Confirm Delete",
                f"Are you sure you want to delete passenger with ID {pid}?\n"
                "This action cannot be undone."):
            return

        # Start performance monitoring
        start_time = time.time()
        initial_memory = psutil.virtual_memory().used / (1024 ** 2)

        try:
            global mongo_manager
            success, message = mongo_manager.delete_passenger(pid)

            # Calculate performance metrics
            end_time = time.time()
            final_memory = psutil.virtual_memory().used / (1024 ** 2)
            execution_time = round(end_time - start_time, 5)
            memory_used = max(0, round(final_memory - initial_memory, 5))

            if success:
                messagebox.showinfo(
                    "Success",
                    f"{message}\n\n"
                    f"Performance Metrics:\n"
                    f"Time: {execution_time} seconds\n"
                    f"Memory: {memory_used} MB"
                )
                delete_window.destroy()
            else:
                status_label.config(text=f"Error: {message}")

            mongo_manager.db_lock.release_window(current_user_id)
            delete_window.destroy()

        except Exception as e:
            mongo_manager.db_lock.release_window(current_user_id)
            delete_window.destroy()
            status_label.config(text=f"Error: {str(e)}")
            print(f"Delete error: {e}")

    def on_window_close():
        mongo_manager.db_lock.release_window(current_user_id)
        delete_window.destroy()

    delete_window.protocol("WM_DELETE_WINDOW", on_window_close)

    # Delete Button
    delete_button = ttk.Button(
        frame,
        text="Delete Passenger",
        command=perform_delete,
        style='Danger.TButton'  # Using a danger style if available
    )
    delete_button.pack(pady=20)

    # Cancel Button
    ttk.Button(
        frame,
        text="Cancel",
        command=delete_window.destroy
    ).pack(pady=5)

    # Set focus to PID entry
    pid_entry.focus()

    # Center the window
    delete_window.update_idletasks()
    width = delete_window.winfo_width()
    height = delete_window.winfo_height()
    x = (delete_window.winfo_screenwidth() // 2) - (width // 2)
    y = (delete_window.winfo_screenheight() // 2) - (height // 2)
    delete_window.geometry(f'{width}x{height}+{x}+{y}')


def analyse_airline_popularity():
    try:
        global mongo_manager
        # Start performance monitoring
        start_time = time.time()
        initial_memory = psutil.virtual_memory().used / (1024 ** 2)

        # Aggregate pipeline to count passengers per airline
        pipeline = [
            {
                "$group": {
                    "_id": "$aid",
                    "passenger_count": {"$sum": 1}
                }
            },
            {
                "$sort": {"passenger_count": -1}
            }
        ]

        results = list(mongo_manager.passengers.aggregate(pipeline))

        if not results:
            messagebox.showinfo("No Data", "No airline popularity data available.")
            return

            # Extract data for plotting
        aids = [result["_id"] for result in results]
        passenger_counts = [result["passenger_count"] for result in results]

        # Plot the horizontal bar chart
        plt.figure(figsize=(10, 6))
        plt.barh(aids, passenger_counts, color='skyblue')
        plt.title('Airline Popularity Based on Passenger Count')
        plt.xlabel('Number of Passengers')
        plt.ylabel('Airline ID')
        plt.gca().invert_yaxis()
        plt.grid(axis='x', linestyle='--', alpha=0.7)
        plt.tight_layout()

        # Calculate performance metrics
        end_time = time.time()
        final_memory = psutil.virtual_memory().used / (1024 ** 2)
        execution_time = round(end_time - start_time, 5)
        memory_used = max(0, round(final_memory - initial_memory, 5))

        # Show the plot
        plt.show()

        # Display results
        most_common = results[0]
        messagebox.showinfo("Airline Popularity Analysis",
                            f"The most common Airline used (Airline: {most_common['_id']}) "
                            f"has {most_common['passenger_count']} passengers.")

        messagebox.showinfo("Performance Metrics",
                            f"Execution Time: {execution_time} seconds\n"
                            f"Memory Used: {memory_used} MB")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
        print(f"Detailed error: {e}")


def analyse_tourism_duration():
    try:
        global mongo_manager
        # Start performance monitoring
        start_time = time.time()
        initial_memory = psutil.virtual_memory().used / (1024 ** 2)

        # Aggregate pipeline to count passengers per length of stay
        pipeline = [
            {
                "$group": {
                    "_id": "$lid",
                    "passenger_count": {"$sum": 1}
                }
            },
            {
                "$sort": {"passenger_count": -1}
            }
        ]

        results = list(mongo_manager.passengers.aggregate(pipeline))

        if not results:
            messagebox.showinfo("No Data", "No tourism duration data available.")
            return

        # Extract data for plotting
        lids = [result["_id"] for result in results]
        passenger_counts = [result["passenger_count"] for result in results]

        # Plotting
        plt.figure(figsize=(10, 6))
        plt.barh(lids, passenger_counts, color='skyblue')
        plt.xlabel("Number of Passengers")
        plt.ylabel("Length of Stay (LID)")
        plt.title("Number of Passengers per Length of Stay")
        plt.gca().invert_yaxis()
        plt.grid(axis='x', linestyle='--', alpha=0.7)
        plt.tight_layout()

        # Calculate performance metrics
        end_time = time.time()
        final_memory = psutil.virtual_memory().used / (1024 ** 2)
        execution_time = round(end_time - start_time, 5)
        memory_used = max(0, round(final_memory - initial_memory, 5))

        # Show the plot
        plt.show()

        # Display results
        most_common = results[0]
        messagebox.showinfo("Tourism Duration Analysis",
                            f"The most common length of stay (LID: {most_common['_id']}) "
                            f"has {most_common['passenger_count']} passengers.")

        messagebox.showinfo("Performance Metrics",
                            f"Execution Time: {execution_time} seconds\n"
                            f"Memory Used: {memory_used} MB")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
        print(f"Detailed error: {e}")


def analyse_airline_trend():
    try:
        global mongo_manager
        # Start performance monitoring
        start_time = time.time()
        initial_memory = psutil.virtual_memory().used / (1024 ** 2)

        # Aggregate pipeline to get passenger count by country and airline
        pipeline = [
            {
                "$group": {
                    "_id": {
                        "country": "$cid",
                        "airline": "$aid"
                    },
                    "count": {"$sum": 1}  # Changed name to avoid confusion
                }
            },
            {
                "$sort": {"_id.country": 1, "_id.airline": 1}
            }
        ]

        results = list(mongo_manager.passengers.aggregate(pipeline))

        if not results:
            messagebox.showinfo("No Data", "No trend data available for airline and country.")
            return

        # Transform data for plotting with explicit column naming
        data = pd.DataFrame([
            {
                'country': r['_id']['country'],
                'airline': r['_id']['airline'],
                'count': r['count']  # Match the name from aggregation
            } for r in results
        ])

        # Verify data
        print("Initial data shape:", data.shape)
        print("Data head:", data.head())

        # Get unique values
        countries = sorted(data['country'].unique())
        airlines = sorted(data['airline'].unique())

        # Create plot
        plt.figure(figsize=(12, 6))
        x = np.arange(len(countries))
        width = 0.8 / len(airlines)

        # Plot each airline's data
        for i, airline in enumerate(airlines):
            # Filter data for this airline
            airline_data = data[data['airline'] == airline]

            # Prepare heights array
            heights = []
            for country in countries:
                # Get count for this country-airline combination
                count = airline_data[airline_data['country'] == country]['count'].values
                heights.append(count[0] if len(count) > 0 else 0)

            # Create bars
            plt.bar(x + i * width,
                    heights,
                    width,
                    label=f'Airline {airline}')

        # Customize plot
        plt.title('Passenger Count by Airline and Country')
        plt.xlabel('Country ID')
        plt.ylabel('Number of Airlines')
        plt.xticks(x + width * (len(airlines) - 1) / 2,
                   [f'{c}' for c in countries],
                   rotation=45)
        plt.legend(title='Airlines',
                   bbox_to_anchor=(1.05, 1),
                   loc='upper left')
        plt.grid(True, axis='y', linestyle='--', alpha=0.7)
        plt.tight_layout()

        # Show plot
        plt.show()

        # Calculate performance metrics
        end_time = time.time()
        final_memory = psutil.virtual_memory().used / (1024 ** 2)
        execution_time = round(end_time - start_time, 5)
        memory_used = max(0, round(final_memory - initial_memory, 5))

        # Display performance metrics
        messagebox.showinfo("Performance Metrics",
                            f"Execution Time: {execution_time} seconds\n"
                            f"Memory Used: {memory_used} MB")

    except Exception as e:
        # Enhanced error reporting
        print(f"Detailed error in analyse_airline_trend: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        traceback.print_exc()
        messagebox.showerror("Error", f"Failed to generate trend plot: {str(e)}")


def start_main_application(token):
    app = MainApplication(token)
    app.run()


def start_login():
    login_window = LoginWindow()
    login_window.run()


connect_to_databases()

# Initialize the application
if __name__ == "__main__":
    if not os.environ.get('APP_SECRET_KEY'):
        os.environ['APP_SECRET_KEY'] = 'your-development-secret-key'

    # Start with login window
    start_login()
