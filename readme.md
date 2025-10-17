# Flask Authentication App

A secure Flask web application with user authentication, session management, and database integration using Supabase PostgreSQL.

## Features

- ✅ User Registration with password validation
- ✅ Secure Login/Logout with Flask-Login
- ✅ Password hashing with Werkzeug
- ✅ Session management with "Remember Me" option
- ✅ PostgreSQL database (Supabase)
- ✅ Responsive UI with gradient design
- ✅ Flash messages for user feedback

## Prerequisites

- Python 3.8+
- PostgreSQL database (Supabase account)
- pip package manager

## Installation

1. **Clone the repository**
```bash
git clone <your-repo-url>
cd flask-auth-app
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure environment variables**

Create a `.env` file in the root directory:
```properties
SECRET_KEY=your-secret-key-here
DATABASE_URL=postgresql://user:password@host:port/database
```

4. **Run the application**
```bash
python app.py
```

5. **Access the app**
Open your browser and go to: `http://localhost:5000`

## Project Structure

```
flask-auth-app/
├── app.py                 # Main application file
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables (not in git)
├── .gitignore            # Git ignore rules
└── templates/
    ├── login.html        # Login page
    ├── signup.html       # Registration page
    └── dashboard.html    # User dashboard
```

## Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number

## Security Notes

- Never commit `.env` file to version control
- Change `SECRET_KEY` in production
- Use strong database passwords
- Enable SSL for database connections

## Technologies Used

- **Flask** - Web framework
- **Flask-SQLAlchemy** - Database ORM
- **Flask-Login** - Session management
- **PostgreSQL** - Database
- **Werkzeug** - Password hashing
- **python-dotenv** - Environment variables

## License

MIT License