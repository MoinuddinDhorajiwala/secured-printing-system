# Document Previewer Web Application

This is a web application for document previewing and management, deployed on Railway.

## Features
- Document upload and preview
- User authentication and management
- Credit system for document processing
- Admin dashboard for user management
- Transaction history
- Responsive web interface

## Deployment
This application is configured for deployment on Railway with PostgreSQL database.

## Environment Variables Required
- `DATABASE_URL`: PostgreSQL connection string (provided by Railway)
- `SECRET_KEY`: Flask secret key for session management
- `MAIL_USERNAME`: Email service username
- `MAIL_PASSWORD`: Email service password

## Files Structure
```
deployment/
├── app.py                 # Main Flask application
├── config.py             # Configuration settings
├── db.py                 # Database connection and operations
├── main2.py              # Additional application modules
├── printer_manager.py    # Document processing utilities
├── email_utils.py        # Email functionality
├── file_converter.py     # File conversion utilities
├── requirements.txt      # Python dependencies
├── Procfile             # Railway deployment configuration
├── railway_config.py    # Railway-specific configuration
├── templates/           # HTML templates
├── static/              # Static files (CSS, JS, images)
└── README.md            # This file
```

## Running Locally
1. Install dependencies: `pip install -r requirements.txt`
2. Set environment variables
3. Run: `python app.py`

## Database
The application uses PostgreSQL database with Railway hosting.